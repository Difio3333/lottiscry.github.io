package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"io"
	"strings"
	"syscall/js"

	"github.com/tink-crypto/tink-go/v2/hybrid"
	"github.com/tink-crypto/tink-go/v2/insecurecleartextkeyset"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/streamingaead"
)

var sessionSigningKey *keyset.Handle
var sessionIdentityKey *keyset.Handle

func generateSessionIdentity(this js.Value, args []js.Value) any {
	var err error

	// 1. Generate both keys in memory
	sessionSigningKey, err = keyset.NewHandle(signature.ED25519KeyTemplate())
	if err != nil {
		return "ERROR: Generating Signing Key: " + err.Error()
	}

	sessionIdentityKey, err = keyset.NewHandle(hybrid.ECIESHKDFAES128GCMKeyTemplate())
	if err != nil {
		return "ERROR: Generating Identity Key: " + err.Error()
	}

	// 2. Extract and encode the Identity Public Key (Half 1)
	pubIdentityHandle, _ := sessionIdentityKey.Public()
	identityBuf := new(bytes.Buffer)
	insecurecleartextkeyset.Write(pubIdentityHandle, keyset.NewBinaryWriter(identityBuf))
	identityBase64 := base64.StdEncoding.EncodeToString(identityBuf.Bytes())

	// 3. Extract and encode the Signing Public Key (Half 2)
	pubSigningHandle, _ := sessionSigningKey.Public()
	signingBuf := new(bytes.Buffer)
	insecurecleartextkeyset.Write(pubSigningHandle, keyset.NewBinaryWriter(signingBuf))
	signingBase64 := base64.StdEncoding.EncodeToString(signingBuf.Bytes())

	// 4. Bundle them together EXACTLY like your Android app does!
	bundledKey := identityBase64 + "." + signingBase64

	return bundledKey
}

func encryptWrapper(this js.Value, args []js.Value) any {
	jsFileData := args[0]
	fileSize := jsFileData.Get("length").Int()
	goFileBytes := make([]byte, fileSize)
	js.CopyBytesToGo(goFileBytes, jsFileData)

	recipientKeyStr := args[1].String()
	fileName := args[2].String()

	// 🚨 THE FIX: Match Kotlin's Bundled Key splitting!
	parts := strings.Split(recipientKeyStr, ".")
	cleanKeyBase64 := strings.TrimSpace(parts[0])

	// --- MATCHING KOTLIN: EXTRACT SENDER HASH ---
	pubSigningHandle, _ := sessionSigningKey.Public()
	senderPubBuf := new(bytes.Buffer)
	insecurecleartextkeyset.Write(pubSigningHandle, keyset.NewBinaryWriter(senderPubBuf))
	senderHash := sha256.Sum256(senderPubBuf.Bytes())

	// --- MATCHING KOTLIN: GENERATE EPHEMERAL KEY ---
	ephemeralHandle, _ := keyset.NewHandle(streamingaead.AES256GCMHKDF4KBKeyTemplate())
	ephBuf := new(bytes.Buffer)
	insecurecleartextkeyset.Write(ephemeralHandle, keyset.NewBinaryWriter(ephBuf))
	rawEphemeralKeyBytes := ephBuf.Bytes()

	// --- MATCHING KOTLIN: RECIPIENT LOCKBOX ---
	// Use the clean, split key here instead of the raw string!
	recipientKeyBytes, err := base64.StdEncoding.DecodeString(cleanKeyBase64)
	if err != nil {
		return "ERROR: Invalid Recipient Key Base64 - " + err.Error()
	}

	recipientHandle, err := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(recipientKeyBytes)))
	if err != nil {
		return "ERROR: Failed to read Recipient Key"
	}

	recipientHash := sha256.Sum256(recipientKeyBytes)
	hybridEncrypt, _ := hybrid.NewHybridEncrypt(recipientHandle)

	contextInfo := []byte("LottisCrypt_v1")
	encryptedStreamingKey, _ := hybridEncrypt.Encrypt(rawEphemeralKeyBytes, contextInfo)

	lockboxesStream := new(bytes.Buffer)
	lockboxesStream.Write(recipientHash[:])

	keySizeBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(keySizeBuf, uint32(len(encryptedStreamingKey)))
	lockboxesStream.Write(keySizeBuf)
	lockboxesStream.Write(encryptedStreamingKey)

	// --- MATCHING KOTLIN: DATA TO SIGN ---
	dataToSign := new(bytes.Buffer)
	dataToSign.Write([]byte("LOTT"))
	dataToSign.Write(senderHash[:])

	recipientCountBuffer := make([]byte, 4)
	binary.BigEndian.PutUint32(recipientCountBuffer, 1)
	dataToSign.Write(recipientCountBuffer)
	dataToSign.Write(lockboxesStream.Bytes())

	// --- MATCHING KOTLIN: SIGNATURE ---
	signer, _ := signature.NewSigner(sessionSigningKey)
	sig, _ := signer.Sign(dataToSign.Bytes())

	signatureSizeBuffer := make([]byte, 4)
	binary.BigEndian.PutUint32(signatureSizeBuffer, uint32(len(sig)))

	// --- MATCHING KOTLIN: FULL HEADER ---
	fullHeader := new(bytes.Buffer)
	fullHeader.Write(dataToSign.Bytes())
	fullHeader.Write(signatureSizeBuffer)
	fullHeader.Write(sig)

	// --- MATCHING KOTLIN: STREAMING AEAD + ZIP ---
	finalOutFile := new(bytes.Buffer)
	finalOutFile.Write(fullHeader.Bytes())

	streamingAeadInstance, _ := streamingaead.New(ephemeralHandle)
	encryptingChannel, _ := streamingAeadInstance.NewEncryptingWriter(finalOutFile, fullHeader.Bytes())

	zipWriter := zip.NewWriter(encryptingChannel)
	fileWriter, _ := zipWriter.CreateHeader(&zip.FileHeader{
		Name:   fileName,
		Method: zip.Deflate, // NO_COMPRESSION
	})

	fileWriter.Write(goFileBytes)
	zipWriter.Close()
	encryptingChannel.Close()

	// --- RETURN TO JAVASCRIPT ---
	jsArray := js.Global().Get("Uint8Array").New(finalOutFile.Len())
	js.CopyBytesToJS(jsArray, finalOutFile.Bytes())

	return jsArray
}

func decryptWrapper(this js.Value, args []js.Value) any {
	jsFileData := args[0]
	fileSize := jsFileData.Get("length").Int()
	fileBytes := make([]byte, fileSize)
	js.CopyBytesToGo(fileBytes, jsFileData)

	reader := bytes.NewReader(fileBytes)

	// --- 1. READ HEADER & VALIDATE ---
	magic := make([]byte, 4)
	reader.Read(magic)
	if string(magic) != "LOTT" {
		return "ERROR: Not a valid LottisCrypt file."
	}

	senderHash := make([]byte, 32)
	reader.Read(senderHash)

	countBuf := make([]byte, 4)
	reader.Read(countBuf)
	recipientCount := binary.BigEndian.Uint32(countBuf)

	// --- 2. FIND OUR LOCKBOX ---
	pubIdentityHandle, _ := sessionIdentityKey.Public()
	identityBuf := new(bytes.Buffer)
	insecurecleartextkeyset.Write(pubIdentityHandle, keyset.NewBinaryWriter(identityBuf))
	myHash := sha256.Sum256(identityBuf.Bytes())

	var myEncryptedKey []byte
	var lockboxesStream bytes.Buffer

	for i := uint32(0); i < recipientCount; i++ {
		recHash := make([]byte, 32)
		reader.Read(recHash)
		lockboxesStream.Write(recHash)

		kSizeBuf := make([]byte, 4)
		reader.Read(kSizeBuf)
		lockboxesStream.Write(kSizeBuf)
		kSize := binary.BigEndian.Uint32(kSizeBuf)

		encKey := make([]byte, kSize)
		reader.Read(encKey)
		lockboxesStream.Write(encKey)

		// If this lockbox matches our Session Identity, save it!
		if bytes.Equal(recHash, myHash[:]) {
			myEncryptedKey = encKey
		}
	}

	if myEncryptedKey == nil {
		return "ERROR: You are not on the authorized recipient list for this file."
	}

	// --- 3. READ SIGNATURE ---
	sigSizeBuf := make([]byte, 4)
	reader.Read(sigSizeBuf)
	sigSize := binary.BigEndian.Uint32(sigSizeBuf)

	signatureData := make([]byte, sigSize)
	reader.Read(signatureData)

	// --- 4. RECONSTRUCT FULL HEADER (For Tink's AES-GCM check) ---
	fullHeader := new(bytes.Buffer)
	fullHeader.Write(magic)
	fullHeader.Write(senderHash)
	fullHeader.Write(countBuf)
	fullHeader.Write(lockboxesStream.Bytes())
	fullHeader.Write(sigSizeBuf)
	fullHeader.Write(signatureData)

	// --- 5. UNLOCK THE EPHEMERAL KEY ---
	hybridDecrypt, _ := hybrid.NewHybridDecrypt(sessionIdentityKey)
	decryptedKeyBytes, err := hybridDecrypt.Decrypt(myEncryptedKey, []byte("LottisCrypt_v1"))
	if err != nil {
		return "ERROR: Failed to unlock lockbox."
	}

	streamingKeyHandle, _ := insecurecleartextkeyset.Read(keyset.NewBinaryReader(bytes.NewReader(decryptedKeyBytes)))
	streamingAeadInstance, _ := streamingaead.New(streamingKeyHandle)

	// --- 6. DECRYPT & UNZIP ---
	decryptingReader, err := streamingAeadInstance.NewDecryptingReader(reader, fullHeader.Bytes())
	if err != nil {
		return "ERROR: Failed to start decryption stream."
	}

	// Read the decrypted ZIP wrapper into memory
	zipBytes, err := io.ReadAll(decryptingReader)
	if err != nil {
		return "ERROR: File payload was tampered with or corrupted."
	}

	zipReader, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil || len(zipReader.File) == 0 {
		return "ERROR: Failed to read internal ZIP structure."
	}

	// Extract the actual file and filename
	file := zipReader.File[0]
	fileName := file.Name
	fileReader, _ := file.Open()
	extractedBytes, _ := io.ReadAll(fileReader)
	fileReader.Close()

	// --- 7. RETURN OBJECT TO JAVASCRIPT ---
	jsObj := js.Global().Get("Object").New()
	jsObj.Set("fileName", fileName)

	jsArray := js.Global().Get("Uint8Array").New(len(extractedBytes))
	js.CopyBytesToJS(jsArray, extractedBytes)
	jsObj.Set("fileData", jsArray)

	return jsObj
}

func main() {
	js.Global().Set("LottisGenerateIdentity", js.FuncOf(generateSessionIdentity))
	js.Global().Set("LottisEncrypt", js.FuncOf(encryptWrapper))
	js.Global().Set("LottisDecrypt", js.FuncOf(decryptWrapper))
	<-make(chan bool)
}

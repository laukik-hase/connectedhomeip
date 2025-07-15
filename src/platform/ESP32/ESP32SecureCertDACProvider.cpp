/*
 *
 *    Copyright (c) 2023 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

#include <credentials/CHIPCert.h>
#include <crypto/CHIPCryptoPAL.h>
#include <esp_fault.h>
#include <esp_log.h>
#include <esp_secure_cert_read.h>
#include <platform/ESP32/ESP32Config.h>
#include <platform/ESP32/ESP32SecureCertDACProvider.h>

#if defined(CONFIG_USE_ESP32_ECDSA_PERIPHERAL) || defined(CONFIG_USE_ESP32_TEE)
#include <platform/ESP32/ESP32CHIPCryptoPAL.h>
#endif // CONFIG_USE_ESP32_ECDSA_PERIPHERAL || CONFIG_USE_ESP32_TEE

#if defined(CONFIG_USE_ESP32_TEE_DAC_KEY_PBKDF2)
#include <platform/ESP32/ESP32FactoryDataProvider.h>
#include "esp_tee_sec_storage.h"
#endif // CONFIG_USE_ESP32_TEE_DAC_KEY_PBKDF2

#define TAG "dac_provider"

#ifdef CONFIG_SEC_CERT_DAC_PROVIDER

namespace chip {
namespace DeviceLayer {

using namespace chip::Credentials;
using namespace chip::DeviceLayer::Internal;

namespace {
static constexpr uint32_t kDACPrivateKeySize = 32;
static constexpr uint32_t kDACPublicKeySize  = 65;
static constexpr uint8_t kPrivKeyOffset      = 7;
static constexpr uint8_t kPubKeyOffset       = 56;
} // namespace

CHIP_ERROR ESP32SecureCertDACProvider ::GetCertificationDeclaration(MutableByteSpan & outBuffer)
{
#ifdef CONFIG_ENABLE_SET_CERT_DECLARATION_API
    return CopySpanToMutableSpan(mCD, outBuffer);
#else
    size_t certSize;
    ReturnErrorOnFailure(
        ESP32Config::ReadConfigValueBin(ESP32Config::kConfigKey_CertDeclaration, outBuffer.data(), outBuffer.size(), certSize));
    outBuffer.reduce_size(certSize);
    return CHIP_NO_ERROR;
#endif // CONFIG_ENABLE_SET_CERT_DECLARATION_API
}

CHIP_ERROR ESP32SecureCertDACProvider ::GetFirmwareInformation(MutableByteSpan & out_firmware_info_buffer)
{
    // We do not provide any FirmwareInformation.
    out_firmware_info_buffer.reduce_size(0);
    return CHIP_NO_ERROR;
}

CHIP_ERROR ESP32SecureCertDACProvider ::GetDeviceAttestationCert(MutableByteSpan & outBuffer)
{
    char * dac_cert  = NULL;
    uint32_t dac_len = 0;

    esp_err_t err = esp_secure_cert_get_device_cert(&dac_cert, &dac_len);
    if (err == ESP_OK && dac_cert != NULL && dac_len != 0)
    {
        ESP_FAULT_ASSERT(err == ESP_OK && dac_cert != NULL && dac_len != 0);
        VerifyOrReturnError(dac_len <= kMaxDERCertLength, CHIP_ERROR_UNSUPPORTED_CERT_FORMAT,
                            esp_secure_cert_free_device_cert(dac_cert));
        VerifyOrReturnError(dac_len <= outBuffer.size(), CHIP_ERROR_BUFFER_TOO_SMALL, esp_secure_cert_free_device_cert(dac_cert));
        memcpy(outBuffer.data(), dac_cert, outBuffer.size());
        outBuffer.reduce_size(dac_len);
        esp_secure_cert_free_device_cert(dac_cert);
        return CHIP_NO_ERROR;
    }

    ESP_LOGE(TAG, "esp_secure_cert_get_device_cert failed err:%d", err);
    return CHIP_ERROR_INCORRECT_STATE;
}

CHIP_ERROR ESP32SecureCertDACProvider ::GetProductAttestationIntermediateCert(MutableByteSpan & outBuffer)
{
    char * pai_cert  = NULL;
    uint32_t pai_len = 0;
    esp_err_t err    = esp_secure_cert_get_ca_cert(&pai_cert, &pai_len);
    if (err == ESP_OK && pai_cert != NULL && pai_len != 0)
    {
        ESP_FAULT_ASSERT(err == ESP_OK && pai_cert != NULL && pai_len != 0);
        VerifyOrReturnError(pai_len <= kMaxDERCertLength, CHIP_ERROR_UNSUPPORTED_CERT_FORMAT,
                            esp_secure_cert_free_ca_cert(pai_cert));
        VerifyOrReturnError(pai_len <= outBuffer.size(), CHIP_ERROR_BUFFER_TOO_SMALL, esp_secure_cert_free_ca_cert(pai_cert));
        memcpy(outBuffer.data(), pai_cert, outBuffer.size());
        outBuffer.reduce_size(pai_len);
        esp_secure_cert_free_ca_cert(pai_cert);
        return CHIP_NO_ERROR;
    }

    ESP_LOGE(TAG, "esp_secure_cert_get_ca_cert failed err:%d", err);
    return CHIP_ERROR_INCORRECT_STATE;
}

CHIP_ERROR ESP32SecureCertDACProvider ::SignWithDeviceAttestationKey(const ByteSpan & messageToSign,
                                                                     MutableByteSpan & outSignBuffer)
{
    esp_err_t esp_err;
    esp_secure_cert_key_type_t keyType;

    CHIP_ERROR chipError;
    Crypto::P256ECDSASignature signature;

    VerifyOrReturnError(!outSignBuffer.empty(), CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(!messageToSign.empty(), CHIP_ERROR_INVALID_ARGUMENT);
    VerifyOrReturnError(outSignBuffer.size() >= signature.Capacity(), CHIP_ERROR_BUFFER_TOO_SMALL);

    esp_err = esp_secure_cert_get_priv_key_type(&keyType);
    VerifyOrReturnError(esp_err == ESP_OK, CHIP_ERROR_INCORRECT_STATE,
                        ESP_LOGE(TAG, "Failed to get the type of private key from secure cert partition, esp_err:%d", esp_err));

    VerifyOrReturnError(keyType != ESP_SECURE_CERT_INVALID_KEY, CHIP_ERROR_INCORRECT_STATE,
                        ESP_LOGE(TAG, "Private key type in secure cert partition is invalid"));

    // This flow is for devices supporting ECDSA peripheral
    if (keyType == ESP_SECURE_CERT_ECDSA_PERIPHERAL_KEY)
    {
        Crypto::ESP32P256Keypair keypair;

#ifdef CONFIG_USE_ESP32_ECDSA_PERIPHERAL
        uint8_t efuseBlockId;

        esp_err = esp_secure_cert_get_priv_key_efuse_id(&efuseBlockId);
        VerifyOrReturnError(esp_err == ESP_OK, CHIP_ERROR_INVALID_KEY_ID,
                            ESP_LOGE(TAG, "Failed to get the private key efuse block id, esp_err:%d", esp_err));

        ESP_LOGD(TAG, "efuse block id:%u", efuseBlockId);

        chipError = keypair.Initialize(chip::Crypto::ECPKeyTarget::ECDSA, efuseBlockId);
        VerifyOrReturnError(chipError == CHIP_NO_ERROR, chipError,
                            ESP_LOGE(TAG, "Failed to initialize the keypair err:%" CHIP_ERROR_FORMAT, chipError.Format()));

        chipError = keypair.ECDSA_sign_msg(messageToSign.data(), messageToSign.size(), signature);
        VerifyOrReturnError(chipError == CHIP_NO_ERROR, chipError,
                            ESP_LOGE(TAG, "Failed to sign with device attestation key, err:%" CHIP_ERROR_FORMAT, chipError.Format()));

#elif defined(CONFIG_USE_ESP32_TEE_DAC_KEY_FLASH)
        const char * key_id = chip::DeviceLayer::Internal::ESP32Config::kConfigKey_DACPrivateKey.Name;

        ESP_LOGD(TAG, "TEE secure storage key id: %s", key_id);

        chipError = keypair.InitializeFromTEE(chip::Crypto::ECPKeyTarget::ECDSA, key_id);
        VerifyOrReturnError(chipError == CHIP_NO_ERROR, chipError,
                            ESP_LOGE(TAG, "Failed to initialize the keypair err:%" CHIP_ERROR_FORMAT, chipError.Format()));

        chipError = keypair.ECDSA_sign_msg(messageToSign.data(), messageToSign.size(), signature);
        VerifyOrReturnError(chipError == CHIP_NO_ERROR, chipError,
                            ESP_LOGE(TAG, "Failed to sign with device attestation key, err:%" CHIP_ERROR_FORMAT, chipError.Format()));

#elif defined(CONFIG_USE_ESP32_TEE_DAC_KEY_PBKDF2)
        /* TODO: Fetch salt from Secure Cert partition */
        uint8_t salt[chip::Crypto::kSpake2p_Max_PBKDF_Salt_Length] = { 0 };
        chip::MutableByteSpan span(salt, sizeof(salt));

        ESP32FactoryDataProvider sFactoryDataProvider;
        chipError = sFactoryDataProvider.GetSpake2pSalt(span);
        VerifyOrReturnError(chipError == CHIP_NO_ERROR, chipError,
                            ESP_LOGE(TAG, "Failed to fetch the PBKDF2 salt err:%" CHIP_ERROR_FORMAT, chipError.Format()));

        uint8_t digest[chip::Crypto::kSHA256_Hash_Length];
        memset(&digest[0], 0, sizeof(digest));
        ReturnErrorOnFailure(chip::Crypto::Hash_SHA256(messageToSign.data(), messageToSign.size(), &digest[0]));

        esp_tee_sec_storage_pbkdf2_ctx_t ctx = {
            .salt = salt,
            .salt_len = sizeof(salt),
            .key_type = ESP_SEC_STG_KEY_ECDSA_SECP256R1
        };

        esp_tee_sec_storage_ecdsa_sign_t sign = {};
        esp_tee_sec_storage_ecdsa_pubkey_t pubkey = {};

        esp_err = esp_tee_sec_storage_ecdsa_sign_pbkdf2(&ctx, digest, sizeof(digest), &sign, &pubkey);
        VerifyOrReturnError(esp_err == ESP_OK, CHIP_ERROR_INTERNAL,
                            ESP_LOGE(TAG, "Failed to sign with device attestation key, esp_err:%d", esp_err));

        memcpy(signature.Bytes() + 0u, sign.sign_r, chip::Crypto::kP256_FE_Length);
        memcpy(signature.Bytes() + chip::Crypto::kP256_FE_Length, sign.sign_s, chip::Crypto::kP256_FE_Length);

        VerifyOrReturnError(signature.SetLength(chip::Crypto::kP256_ECDSA_Signature_Length_Raw) == CHIP_NO_ERROR, chipError = CHIP_ERROR_INTERNAL);
#else
        return CHIP_ERROR_INCORRECT_STATE;
#endif // CONFIG_USE_ESP32_ECDSA_PERIPHERAL
    }
    else // This flow is for devices which do not support ECDSA peripheral
    {
#ifndef CONFIG_USE_ESP32_ECDSA_PERIPHERAL
        Crypto::P256Keypair keypair;
        char * sc_keypair       = NULL;
        uint32_t sc_keypair_len = 0;

        esp_err = esp_secure_cert_get_priv_key(&sc_keypair, &sc_keypair_len);
        VerifyOrReturnError(esp_err == ESP_OK && sc_keypair != NULL && sc_keypair_len != 0, CHIP_ERROR_INCORRECT_STATE,
                            ESP_LOGE(TAG, "esp_secure_cert_get_priv_key failed esp_err:%d", esp_err));

        ESP_FAULT_ASSERT(esp_err == ESP_OK && sc_keypair != NULL && sc_keypair_len != 0);

        chipError = keypair.HazardousOperationLoadKeypairFromRaw(
            ByteSpan(reinterpret_cast<const uint8_t *>(sc_keypair + kPrivKeyOffset), kDACPrivateKeySize),
            ByteSpan(reinterpret_cast<const uint8_t *>(sc_keypair + kPubKeyOffset), kDACPublicKeySize));
        VerifyOrReturnError(chipError == CHIP_NO_ERROR, chipError, esp_secure_cert_free_priv_key(sc_keypair));

        chipError = keypair.ECDSA_sign_msg(messageToSign.data(), messageToSign.size(), signature);
        VerifyOrReturnError(chipError == CHIP_NO_ERROR, chipError, esp_secure_cert_free_priv_key(sc_keypair));

        esp_secure_cert_free_priv_key(sc_keypair);
#else
        return CHIP_ERROR_INCORRECT_STATE;
#endif // !CONFIG_USE_ESP32_ECDSA_PERIPHERAL
    }
    return CopySpanToMutableSpan(ByteSpan{ signature.ConstBytes(), signature.Length() }, outSignBuffer);
}

} // namespace DeviceLayer
} // namespace chip

#endif // CONFIG_SEC_CERT_DAC_PROVIDER

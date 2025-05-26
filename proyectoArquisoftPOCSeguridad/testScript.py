import unittest
import boto3
import hashlib
import base64
from botocore.exceptions import ClientError

# Setup KMS client
session = boto3.Session(profile_name='doctor_a')
kms = session.client('kms', region_name='us-east-2')

session_b = boto3.Session(profile_name='doctor_b')
kms_b = session_b.client('kms', region_name='us-east-2')

# Dummy documents to sign
DOCUMENT_A = "Patient John Doe - Clinic visit notes v1"
DOCUMENT_B = "Patient John Doe - Updated notes v2"

# Doctor keys (replace with your actual key IDs or aliases)
DOCTOR_A_KEY_ID = '944d152a-9618-4ba5-a868-645915604b40'
DOCTOR_B_KEY_ID = '6930c015-7cc6-4b74-a9b5-1e99e55dc993'

def sha256_digest(data: str) -> bytes:
    return hashlib.sha256(data.encode()).digest()

def sign_document(kms_client, key_id: str, document: str) -> bytes:
    digest = sha256_digest(document)
    response = kms_client.sign(
        KeyId=key_id,
        Message=digest,
        SigningAlgorithm='RSASSA_PSS_SHA_256',
        MessageType='DIGEST'
    )
    return response['Signature']

def verify_signature(kms_client, key_id: str, document: str, signature: bytes) -> bool:
    digest = sha256_digest(document)
    try:
        response = kms_client.verify(
            KeyId=key_id,
            Message=digest,
            Signature=signature,
            SigningAlgorithm='RSASSA_PSS_SHA_256',
            MessageType='DIGEST'
        )
        return response['SignatureValid']
    except ClientError as e:
        #print(f"Verification failed: {e}")
        return False

class TestClinicalHistorySigning(unittest.TestCase):

    def test_normal_modification_sign_and_verify(self):
        for i in range(2):
            with self.subTest(i=i):
                # Doctor A signs document A
                signature = sign_document(kms,DOCTOR_A_KEY_ID, DOCUMENT_A)
                # Verify signature
                self.assertTrue(verify_signature(kms,DOCTOR_A_KEY_ID, DOCUMENT_A, signature))

    def test_unauthorized_signing_attempt(self):
        # Doctor B tries to sign with Doctor A's key (simulate by using Doctor A's key but you should test IAM policy)
        # Here we simulate an unauthorized call by trying to sign with Doctor A's key as Doctor B
        # In real, this will fail at AWS IAM policy level and raise ClientError
        # For demo, we expect an exception or deny.
        for i in range(2):
            with self.subTest(i=i):
                with self.assertRaises(ClientError) as cm:
                    sign_document(kms_b,DOCTOR_A_KEY_ID, DOCUMENT_B)
                self.assertIn('AccessDeniedException', str(cm.exception))
##
    def test_tampered_document_detection(self):
        for i in range(2):
            with self.subTest(i=i):
            # Doctor A signs document A
                signature = sign_document(kms,DOCTOR_A_KEY_ID, DOCUMENT_A)
                # Tampered document
                tampered_doc = DOCUMENT_A + " (tampered)"
                # Verification must fail
                self.assertFalse(verify_signature(kms,DOCTOR_A_KEY_ID, tampered_doc, signature))

    
    def test_multiple_sequential_updates(self):
        for i in range(2):
            DOCUMENT= f"Patient Jane Doe - Clinic visit notes Iteration{i}"
            with self.subTest(i=i):
                # Doctor A signs DOCUMENT_A
                sig_a = sign_document(kms,DOCTOR_A_KEY_ID, DOCUMENT)
                self.assertTrue(verify_signature(kms,DOCTOR_A_KEY_ID, DOCUMENT, sig_a))
                # Doctor B signs DOCUMENT_B
                sig_b = sign_document(kms_b,DOCTOR_B_KEY_ID, DOCUMENT)
            self.assertTrue(verify_signature(kms_b,DOCTOR_B_KEY_ID, DOCUMENT, sig_b))

if __name__ == '__main__':
    unittest.main()

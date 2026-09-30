import hashlib
def get_hash(config_text):
    # This creates a unique digital fingerprint for the text
    return hashlib.md5(config_text.encode()).hexdigest()
# Imagine netmiko pulls the text here, and we check the hash before saving.
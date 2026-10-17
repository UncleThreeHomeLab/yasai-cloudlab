"""Native HTTP backend and enforced client encryption environment."""
import json
import os


def environment(values, url, passphrase):
    result = {key: os.environ[key] for key in ('PATH', 'HOME') if key in os.environ}
    result['TF_CLI_CONFIG_FILE'] = '/opt/runner/providers.tfrc'
    result.update(TF_HTTP_ADDRESS=url, TF_HTTP_LOCK_ADDRESS=url + '/lock',
                  TF_HTTP_UNLOCK_ADDRESS=url + '/lock', TF_HTTP_LOCK_METHOD='POST',
                  TF_HTTP_UNLOCK_METHOD='DELETE', TF_HTTP_USERNAME=values['USERNAME'],
                  TF_HTTP_PASSWORD=values['TOKEN'], TF_HTTP_RETRY_MAX='0', TF_IN_AUTOMATION='true')
    result['TF_ENCRYPTION'] = '''key_provider "pbkdf2" "recovery" {
  passphrase = %s
}
method "aes_gcm" "protected" {
  keys = key_provider.pbkdf2.recovery
}
state {
  method = method.aes_gcm.protected
  enforced = true
}
plan {
  method = method.aes_gcm.protected
  enforced = true
}
''' % json.dumps(passphrase)
    return result

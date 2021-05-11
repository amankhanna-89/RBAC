import rsa

admin_email = 'a'
admin_password = 'adminpw'

user_email = 'aman@ok.com'
user_password = 'amanpw'

publicKey, privateKey = rsa.newkeys(512)

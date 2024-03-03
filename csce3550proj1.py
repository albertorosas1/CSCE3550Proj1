from flask import Flask, request, jsonify
import jwt
import uuid
import base64
import rsa
import time


app = Flask(__name__) #create our application instance

jwks_keys=[] #declar jwks keys dict



def newJWK():
    pub_key, priv_key = rsa.newkeys(2048) #general new keys
    global key_id #
    global priv_key_pem #declare global variables
    key_id = str(uuid.uuid4()) #generate kid
    priv_key_pem = priv_key.save_pkcs1().decode('utf-8')
    n = pub_key.n
    e = pub_key.e
    n_base64 = base64.b64encode(n.to_bytes((n.bit_length() + 7) // 8, byteorder='big')).decode('utf-8').rstrip('=')
    e_base64 = base64.b64encode(e.to_bytes((e.bit_length() + 7) // 8, byteorder='big')).decode('utf-8')
    jwk = {
    "kty": "RSA", #set type
    "alg": "RS256", #set algorithim
    "use": "sig",
    "kid": key_id, #set our kid
    "n": n_base64,#set encode n to n
    "e": e_base64 #set encoded e to e 
}
    jwks_keys.append(jwk) #append our new jwk

  


# Endpoint to serve JWKS
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks_get():
    jwks = {"keys": jwks_keys}
    return jwks #return out jwks on get call 



# Endpoint to authenticate and issue JWTs
@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired') #check for expired arg
    expir = 2000 #initalize expir
    newJWK() #call new jwk function
    now = int(time.time()) #get our now time
    
    
    if expired is None: #check if expired flag is present
       expir = expir
    else: #if the flag is present
        if expired: #if the flag is true
            expir -= now #set expir to negative
        else:
            expir += 2000  #set expir
    payload = {
    "exp": now + expir, #adjust expiration time
        }
    myJwt = jwt.encode(payload, priv_key_pem, algorithm = "RS256", headers={"kid": key_id}) #encode token
     
    
    
    
    return (myJwt) #return our token


if __name__ == '__main__':
    app.run(port=8080) #run our application

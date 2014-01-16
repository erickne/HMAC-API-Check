# HMAC-API-Check #


This is a PHP class to secure REST API requests from clients using HMAC and without credentials.


### Motivation ###

Check this link: [Designing a Secure REST (Web) API without OAuth](http://www.thebuzzmedia.com/designing-a-secure-rest-api-without-oauth-authentication/). I needed some secure method to send payments data across web.

### Benefitis ###

This is a safe way to validate requests from clients and prevent [Replay Attacks](http://en.wikipedia.org/wiki/Replay_attack).

### Usage ###

The code sent from client must
* Be an array
* Encoded with ``json_encode``
* Have the following keys: ``api_key``, ``uri``,``sent_at`` and ``data``.

#### Step 1: Setting up database ####

Build an table with fields <b>api_code</b> (unique) and <b>private_key</b>.

#### Step 2: Setting up values ####

    //This is a public key. A middle man can have this.
    $user_api_key = "1234567890";
    
    //This is a private key. NEVER send this value.
    $user_pvt_key = "AAABBBCCCDDDEEE";

    $_data_private = array(
        'api_key' => $user_api_key,
        'uri' =>'teste/robot/b',
        'sent_at' => date("Y-m-d H:i:s", time()), 
        'data' => array(
            'id' => '550',
            'name' => 'erick',
            'age' => '30',
        );
    );

#### Step 3: Crypt values ####
Now it's time to encrypt all values and save in the key ``['hash']``. First select the method (sha1) then ``json_encode`` your array. The last argument is yout private key. 

    $_data_private['hash'] = hash_hmac('sha1', json_encode($_data_private), $user_pvt_key);
      
      
#### Step 4 : Client validation ####

After your server receives the package, you grab ``api_key`` value and check for his <b>private key </b> (``$user_private_key``) value in database (Step 1).

    $hmac = new HMAC( $_data_private , $user_private_key );
    $hmac->isValid();

And that's it. If this method returns true, you can use data from ``$_data_private['data']`` safely.

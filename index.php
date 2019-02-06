<?php


    // WtVdmEF9XQWRB9uiIpmq5JrTyQbIUeKmEtO+Hrb63qE=
    $string = "byScwFjDfnNEPTxZykORQfx7q97js+zJPcMYo62zSeA=";
    echo ed2($string, 'd');
    function ed2($string, $action = 'e') {
        $plaintext = $string;
        $password = 'l;ylfu9vog=hk';

        // CBC has an IV and thus needs randomness every time a message is encrypted
        $method = 'aes-256-cbc';

        // Must be exact 32 chars (256 bit)
        // You must store this secret random key in a safe place of your system.
        $key = substr(hash('sha256', $password, true), 0, 32);
        // echo "Password:" . $password . "\n";

        // Most secure key
        //$key = openssl_random_pseudo_bytes(openssl_cipher_iv_length($method));

        // IV must be exact 16 chars (128 bit)
        $iv = chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0) . chr(0x0);

        // Most secure iv
        // Never ever use iv=0 in real live. Better use this:
        // $ivlen = openssl_cipher_iv_length($method);
        // $iv = openssl_random_pseudo_bytes($ivlen);

        $output = false;
        if ($action == 'e') {
            $output = base64_encode(openssl_encrypt($plaintext, $method, $key, OPENSSL_RAW_DATA, $iv));
        } else if ($action == 'd') {
            $output = openssl_decrypt(base64_decode($plaintext), $method, $key, OPENSSL_RAW_DATA, $iv);
        }
        return $output;
}
?>
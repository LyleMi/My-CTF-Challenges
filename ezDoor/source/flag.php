<?php

function encode($string){
    $hex='';
    for ($i=0; $i < strlen($string); $i++){
        $tmp = dechex(ord($string[$i]));
        if(strlen($tmp) == 1){
            $hex .= "0" . $tmp;
        }else{
            $hex .= $tmp;
        }
    }
    return $hex;
}

function encrypt($pwd, $data){
    mt_srand(1337);
    $cipher = "";
    $pwd_length = strlen($pwd);
    $data_length = strlen($data);
    for ($i = 0; $i < $data_length; $i++) {
        $cipher .= chr(ord($data[$i]) ^ ord($pwd[$i % $pwd_length]) ^ mt_rand(0, 255));
    }
    return encode($cipher);
}

$flag = "input_your_flag_here";

if(encrypt("this_is_a_very_secret_key", $flag) === "85b954fc8380a466276e4a48249ddd4a199fc34e5b061464e4295fc5020c88bfd8545519ab") { 
    echo "Congratulation! You got it!";
} else {
    echo "Wrong Answer";
}

exit();


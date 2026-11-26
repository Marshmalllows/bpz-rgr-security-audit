<?php

/*

bWAPP, or a buggy web application, is a free and open source deliberately insecure web application.
It helps security enthusiasts, developers and students to discover and to prevent web vulnerabilities.
bWAPP covers all major known web vulnerabilities, including all risks from the OWASP Top 10 project!
It is for security-testing and educational purposes only.

Enjoy!

Malik Mesellem
Twitter: @MME_IT

bWAPP is licensed under a Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International License (http://creativecommons.org/licenses/by-nc-nd/4.0/). Copyright © 2014 MME BVBA. All rights reserved.

*/


include("security.php");
include("security_level_check.php");
include("functions_external.php");

header("Content-Type: application/json; charset=utf-8");
header("X-Content-Type-Options: nosniff");

if(isset($_GET["title"]))
{

    $movies = array("CAPTAIN AMERICA", "IRON MAN", "SPIDER-MAN", "THE INCREDIBLE HULK", "THE WOLVERINE", "THOR", "X-MEN");

    $title = $_GET["title"];

    if(in_array(strtoupper($title), $movies))
        $response = "Yes! We have that movie...";
    else if(trim($title) == "")
        $response = "HINT: our master really loves Marvel movies :)";
    else
        $response = $title . "??? Sorry, we don't have that movie :(";

}

else
{

    $response = "Try harder :p";

}

echo json_encode(array("movies" => array(array("response" => $response))));

// Multiple entries
/*
$movies = array(
    "movies" => array(
        array(
            "title" => "Iron Man"
        ),
        array(
            "title" => "Captain America"
        )
    )
);
*/

?>
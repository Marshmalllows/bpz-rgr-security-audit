<?php

function html_encode($data)
{

    return htmlspecialchars($data, ENT_QUOTES, "UTF-8");

}

function js_encode($data)
{

    return json_encode($data, JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_PARTIAL_OUTPUT_ON_ERROR);

}

?>

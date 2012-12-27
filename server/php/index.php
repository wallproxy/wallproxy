<?php

// Contributor:
//      Phus Lu        <phus.lu@gmail.com>
//      Parkman Zhou   <cseparkman@gmail.com>
//      Gwjwin         <gwjwin@hotmail.com>

// Changes log:
//      Post data uncompress fixed
//      Password support
//      Chunked transfer fixed

$__version__  = '1.10.1';
$__password__ = '';
$__timeout__  = 20;

$chunked = 0;

function encode_data($dic) {
    $a = array();
    foreach ($dic as $key => $value) {
        if ($value) {
            $a[] = $key. '=' . bin2hex($value);
        }
    }
    return join('&', $a);
}

function decode_data($qs) {
    $dic = array();
    foreach (explode('&', $qs) as $kv) {
        $pair = explode('=', $kv, 2);
        $dic[$pair[0]] = $pair[1] ? pack('H*', $pair[1]) : '';
    }
    return $dic;
}

function header_function($ch, $header){
    //check 'Transfer-Encoding: chunked' header
    if (strpos($header,"Transfer-Encoding: chunked")===0) {
        $GLOBALS['chunked'] = 1;
    }
    header($header);
    $GLOBALS['header_length'] += 1;
    return strlen($header);
}

function write_function($ch, $body){
    //has 'chunked' header?
    if ($GLOBALS['chunked']){
        printf("%x\r\n%s\r\n", strlen($body), $body);
    }else{
        echo $body;
    }
    $GLOBALS['body_length'] += 1;
    return strlen($body);
}

function post()
{
    $request = @decode_data(@gzuncompress(base64_decode($_SERVER['HTTP_COOKIE'])));
    $method  = $request['method'];
    $url     = $request['url'];
    $password = $request['password'];

    if ($password != $GLOBALS['__password__']){
        echo 'Invalid Password.';
        exit(-1);
    }

    $headers = array();
    foreach (explode("\r\n", $request['headers']) as $line) {
        $pair = explode(':', $line, 2);
        if (count($pair) == 2) {
            $headers[trim(strtolower($pair[0]))] = trim($pair[1]);
        }
    }
    $headers['connection'] = 'close';
    $body = @file_get_contents('php://input');
    $timeout = $GLOBALS['__timeout__'];

    $response_headers = array();

    if ($body) {
        $headers['content-length'] = strval(strlen($body));
    }
    $headers['connection'] = 'close';


    $curl_opt = array();

    $curl_opt[CURLOPT_RETURNTRANSFER] = true;
    $curl_opt[CURLOPT_BINARYTRANSFER] = true;

    $curl_opt[CURLOPT_HEADER]         = false;
    $curl_opt[CURLOPT_HEADERFUNCTION] = 'header_function';
    $curl_opt[CURLOPT_WRITEFUNCTION]  = 'write_function';


    $curl_opt[CURLOPT_FAILONERROR]    = true;
    $curl_opt[CURLOPT_FOLLOWLOCATION] = false;

    $curl_opt[CURLOPT_CONNECTTIMEOUT] = $timeout;
    $curl_opt[CURLOPT_TIMEOUT]        = $timeout;

    $curl_opt[CURLOPT_SSL_VERIFYPEER] = false;
    $curl_opt[CURLOPT_SSL_VERIFYHOST] = false;

    switch (strtoupper($method)) {
        case 'HEAD':
            $curl_opt[CURLOPT_NOBODY] = true;
            break;
        case 'GET':
            break;
        case 'POST':
            $curl_opt[CURLOPT_POST] = true;
            $curl_opt[CURLOPT_POSTFIELDS] = $body;
            break;
        case 'PUT':
            break;
        case 'DELETE':
            $curl_opt[CURLOPT_CUSTOMREQUEST] = $method;
            $curl_opt[CURLOPT_POSTFIELDS] = $body;
            break;
        case 'CONNECT':
            exit;
        default:
            echo 'Invalid Method: '. $method;
            exit(-1);
    }

    $header_array = array();
    foreach ($headers as $key => $value) {
        if ($key) {
            $header_array[] = join('-', array_map('ucfirst', explode('-', $key))).': '.$value;
        }
    }
    $curl_opt[CURLOPT_HTTPHEADER] = $header_array;

    $ch = curl_init($url);
    curl_setopt_array($ch, $curl_opt);
    $ret = curl_exec($ch);
    //chunked end
    if ($GLOBALS['chunked']){
        echo "0\r\n\r\n";
    }
    //$status_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $errno = curl_errno($ch);
    if ($errno && !isset($GLOBALS['header_length'])) {
        echo $errno . ': ' .curl_error($ch);
    }
    curl_close($ch);
}

function get() {
    header('Location: http://www.google.com/');
}

function main() {
    if ($_SERVER['REQUEST_METHOD'] == 'POST') {
        post();
    } else {
        get();
    }
}

main();

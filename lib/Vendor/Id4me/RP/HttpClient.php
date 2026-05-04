<?php

namespace OCA\UserOIDC\Vendor\Id4me\RP;

interface HttpClient
{
    public function get($url, array $headers = []);
    public function post($url, $body, array $headers = []);
}

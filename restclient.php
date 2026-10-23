<?php
/**
 *    Nombre:       restclient.php
 *    Descripcion:  Cliente REST de Madelan, fork de tcdent/php-restclient 0.1.7: una sola version para todos los
 *                  proyectos, con la verificacion TLS prendida, el armado de URL que necesita GX y compatible con
 *                  PHP 8.3 (RXI-2365)
 *    Version:      1.0.0
 *    Creado:       23-10-2026
 *    Modificado:   23-10-2026
 *    Autor:        Sebastian Toyos
 */

/**
 * PHP REST Client
 * https://github.com/tcdent/php-restclient
 * (c) 2013-2017 Travis Dent <tcdent@gmail.com>
 */

class RestClientException extends Exception {}

class RestClient implements Iterator, ArrayAccess {
    
    public $options;
    public $handle; // cURL resource handle.
    
    // Populated after execution:
    public $response; // Response body.
    public $headers; // Parsed reponse header object.
    public $info; // Response info object.
    public $error; // Response error string.
    //? RXI-2365: execute() la escribe en el clon; sin declarar es una propiedad dinamica, deprecada en PHP 8.2
    public $url;
    public $response_status_lines; // indexed array of raw HTTP response status lines.
    
    // Populated as-needed.
    public $decoded_response; // Decoded response body. 
    
    public function __construct($options=[]){
        $default_options = [
            'headers' => [], 
            'parameters' => [], 
            'curl_options' => [], 
            'build_indexed_queries' => FALSE, 
            'user_agent' => "PHP RestClient/0.1.7", 
            'base_url' => NULL, 
            'format' => NULL, 
            'format_regex' => "/(\w+)\/(\w+)(;[.+])?/",
            'decoders' => [
                'json' => 'json_decode', 
                'php' => 'unserialize'
            ], 
            'username' => NULL, 
            'password' => NULL
        ];
        
        $this->options = array_merge($default_options, $options);
        if(array_key_exists('decoders', $options))
            $this->options['decoders'] = array_merge(
                $default_options['decoders'], $options['decoders']);
    }
    
    public function set_option($key, $value){
        $this->options[$key] = $value;
    }
    
    public function register_decoder($format, $method){
        // Decoder callbacks must adhere to the following pattern:
        //   array my_decoder(string $data)
        $this->options['decoders'][$format] = $method;
    }
    
    // Iterable methods:
    //? MDLLOTES-1409: #[\ReturnTypeWillChange] evita el Deprecated de PHP 8.1+ en los metodos de Iterator y ArrayAccess,
    //? que no declaran tipo de retorno. En PHP 7 el #[...] se lee como comentario.
    //? RXI-2365: json_decode devuelve un objeto, y reset(), current(), key() y next() sobre un objeto estan deprecados
    //? desde PHP 8.1. valid() ya cortaba con todo lo que no es array, asi que el foreach no cambia.
    #[\ReturnTypeWillChange]
    public function rewind(){
        $this->decode_response();
        return is_array($this->decoded_response)? reset($this->decoded_response) : FALSE;
    }
    
    #[\ReturnTypeWillChange]
    public function current(){
        return is_array($this->decoded_response)? current($this->decoded_response) : FALSE;
    }
    
    #[\ReturnTypeWillChange]
    public function key(){
        return is_array($this->decoded_response)? key($this->decoded_response) : NULL;
    }
    
    #[\ReturnTypeWillChange]
    public function next(){
        return is_array($this->decoded_response)? next($this->decoded_response) : FALSE;
    }
    
    #[\ReturnTypeWillChange]
    public function valid(){
        return is_array($this->decoded_response)
            && (key($this->decoded_response) !== NULL);
    }
    
    // ArrayAccess methods:
    #[\ReturnTypeWillChange]
    public function offsetExists($key){
        $this->decode_response();
        return is_array($this->decoded_response)?
            isset($this->decoded_response[$key]) : isset($this->decoded_response->{$key});
    }
    
    #[\ReturnTypeWillChange]
    public function offsetGet($key){
        $this->decode_response();
        if(!$this->offsetExists($key))
            return NULL;
        
        return is_array($this->decoded_response)?
            $this->decoded_response[$key] : $this->decoded_response->{$key};
    }
    
    #[\ReturnTypeWillChange]
    public function offsetSet($key, $value){
        throw new RestClientException("Decoded response data is immutable.");
    }
    
    #[\ReturnTypeWillChange]
    public function offsetUnset($key){
        throw new RestClientException("Decoded response data is immutable.");
    }
    
    // Request methods:
    public function get($url, $parameters=[], $headers=[]){
        return $this->execute($url, 'GET', $parameters, $headers);
    }
    
    public function post($url, $parameters=[], $headers=[]){
        return $this->execute($url, 'POST', $parameters, $headers);
    }
    
    public function put($url, $parameters=[], $headers=[]){
        return $this->execute($url, 'PUT', $parameters, $headers);
    }
    
    public function patch($url, $parameters=[], $headers=[]){
        return $this->execute($url, 'PATCH', $parameters, $headers);
    }
    
    public function delete($url, $parameters=[], $headers=[]){
        return $this->execute($url, 'DELETE', $parameters, $headers);
    }
    
    public function head($url, $parameters=[], $headers=[]){
        return $this->execute($url, 'HEAD', $parameters, $headers);
    }
    
    public function execute($url, $method='GET', $parameters=[], $headers=[]){
        $client = clone $this;
        $client->url = $url;
        $client->handle = curl_init();
        $curlopt = [
            CURLOPT_HEADER => TRUE, 
            CURLOPT_RETURNTRANSFER => TRUE, 
            CURLOPT_USERAGENT => $client->options['user_agent'],
            //? MDLLOTES-1409, RXI-2365: verificacion TLS prendida. VERIFYHOST 2 valida el dominio del certificado y
            //? VERIFYPEER la cadena contra el CA bundle (curl.cainfo del php.ini). Con las dos en 0 alguien en el medio
            //? podia capturar el X-Auth-Token. Un endpoint con certificado propio pasa su CURLOPT_CAINFO en curl_options.
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_SSL_VERIFYPEER => TRUE,
            //? RXI-2365: HTTP/1.0 como en las copias de los proyectos (golotes pwa lo habia sacado en MDLLOTES-1409)
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_0
        ];
        
        if($client->options['username'] && $client->options['password'])
            $curlopt[CURLOPT_USERPWD] = sprintf("%s:%s", 
                $client->options['username'], $client->options['password']);
        
        if(count($client->options['headers']) || count($headers)){
            $curlopt[CURLOPT_HTTPHEADER] = [];
            $headers = array_merge($client->options['headers'], $headers);
            foreach($headers as $key => $values){
                foreach(is_array($values)? $values : [$values] as $value){
                    $curlopt[CURLOPT_HTTPHEADER][] = sprintf("%s:%s", $key, $value);
                }
            }
        }
        
        //? Fix para GX: la extension del formato no se agrega a la URL. 'format' se usa solo para decodificar la respuesta
        
        // Allow passing parameters as a pre-encoded string (or something that
        // allows casting to a string). Parameters passed as strings will not be
        // merged with parameters specified in the default options.
        if(is_array($parameters)){
            $parameters = array_merge($client->options['parameters'], $parameters);
            $parameters_string = http_build_query($parameters);
            
            // http_build_query automatically adds an array index to repeated
            // parameters which is not desirable on most systems. This hack
            // reverts "key[0]=foo&key[1]=bar" to "key[]=foo&key[]=bar"
            if(!$client->options['build_indexed_queries'])
                $parameters_string = preg_replace(
                    "/%5B[0-9]+%5D=/simU", "%5B%5D=", $parameters_string);
        }
        else
            $parameters_string = (string) $parameters;
        
        if(strtoupper($method) == 'POST'){
            $curlopt[CURLOPT_POST] = TRUE;
            $curlopt[CURLOPT_POSTFIELDS] = $parameters_string;
        }
        elseif(strtoupper($method) != 'GET'){
            $curlopt[CURLOPT_CUSTOMREQUEST] = strtoupper($method);
            $curlopt[CURLOPT_POSTFIELDS] = $parameters_string;
        }
        elseif($parameters_string){
            $client->url .= strpos($client->url, '?')? '&' : '?';
            $client->url .= $parameters_string;
        }
        
        //? Fix para GX: base_url y la ruta se pegan tal cual, sin la "/" que el original agregaba entre las dos
        if($client->options['base_url']){
            $client->url = $client->options['base_url'] . $client->url;
        }
        $curlopt[CURLOPT_URL] = $client->url;
        
        if($client->options['curl_options']){
            // array_merge would reset our numeric keys.
            foreach($client->options['curl_options'] as $key => $value){
                $curlopt[$key] = $value;
            }
        }
        curl_setopt_array($client->handle, $curlopt);
        
        $client->parse_response(curl_exec($client->handle));
        $client->info = (object) curl_getinfo($client->handle);
        $client->error = curl_error($client->handle);
        
        curl_close($client->handle);
        return $client;
    }
    
    public function parse_response($response){
        $headers = [];
        $this->response_status_lines = [];
        $line = strtok($response, "\n");
        do {
            if(strlen(trim($line)) == 0){
                // Since we tokenize on \n, use the remaining \r to detect empty lines.
                if(count($headers) > 0) break; // Must be the newline after headers, move on to response body
            }
            elseif(strpos($line, 'HTTP') === 0){
                // One or more HTTP status lines
                $this->response_status_lines[] = trim($line);
            }
            else { 
                // Has to be a header
                list($key, $value) = explode(':', $line, 2);
                $key = trim(strtolower(str_replace('-', '_', $key)));
                $value = trim($value);
                
                if(empty($headers[$key]))
                    $headers[$key] = $value;
                elseif(is_array($headers[$key]))
                    $headers[$key][] = $value;
                else
                    $headers[$key] = [$headers[$key], $value];
            }
        } while($line = strtok("\n"));
        
        $this->headers = (object) $headers;
        $this->response = strtok("");
    }
    
    public function get_response_format(){
        if(!$this->response)
            throw new RestClientException(
                "A response must exist before it can be decoded.");
        
        // User-defined format. 
        if(!empty($this->options['format']))
            return $this->options['format'];
        
        // Extract format from response content-type header. 
        if(!empty($this->headers->content_type))
        if(preg_match($this->options['format_regex'], $this->headers->content_type, $matches))
            return $matches[2];
        
        throw new RestClientException(
            "Response format could not be determined.");
    }
    
    public function decode_response(){
        if(empty($this->decoded_response)){
            
            $format = $this->get_response_format();
            
            if(!array_key_exists($format, $this->options['decoders']))
                throw new RestClientException("'{$format}' is not a supported ".
                    "format, register a decoder to handle this response.");
            
            $this->decoded_response = call_user_func(
                $this->options['decoders'][$format], $this->response);
        }
        
        return $this->decoded_response;
    }
}



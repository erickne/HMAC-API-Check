<?php

/**
 * HMAC-API-Check
 * 
 * This is a class to validate information sent by a specific client in a secure way.
 * @link https://github.com/erickne/HMAC-API-Check
 * @author Erick Engelhardt  
 */
Class HMAC {

  var $private_key;
  var $api_key;
  
  private $algorithm;
  
  private $data_package;
  private $data_hash_client;
  private $data_hash_server;
  
  private $time_interval;
  private $time_interval_max; // in seconds  
  
  private $date_client_sent;
  private $date_server_received;
  
  public $valid_date = NULL;
  public $valid_hash = NULL;
  public $valid = NULL;
  
  public function __construct($data_client,$private_key, $algorithm = 'sha1' , $time_interval_max = 600){

    /* This is a bypass to test time changes.
    $date = date_create(date("Y-m-d H:i:s", time()));
    date_add($date, date_interval_create_from_date_string('+10 min'));
    $this->date_server_received = date_format($date, 'Y-m-d H:i:s');
    */
    $this->date_server_received = date("Y-m-d H:i:s", time());
    
    $this->time_interval_max = $time_interval_max;
    $this->algorithm = $algorithm;

    $this->data_package = $data_client;
    unset($this->data_package['hash']);
    $this->date_client_sent = $data_client['sent_at'];
    $this->api_key = $data_client['api_key'];
    $this->data_hash_client = $data_client['hash'];
    
    $this->private_key = $private_key;

    $this->isValid();
  }
  
  public function generateHash(){
    $this->data_hash_server = hash_hmac($this->algorithm, json_encode($this->data_package), $this->private_key);
    return $this;
  }
  
  public function compareDate(){

    $ts1 = strtotime(date($this->date_client_sent));
    $ts2 = strtotime(date($this->date_server_received));
    
    $this->time_interval = abs($ts2 - $ts1);
    
    if($this->time_interval > $this->time_interval_max) {
      $this->valid_date = false;
      return false;
    } else {
      $this->valid_date = true;
      return true;      
    } 
  }
  
  public function compareHash(){
      
    $this->generateHash();
    
    if($this->data_hash_client == $this->data_hash_server) {
      $this->valid_hash = true;
      return true;
    } else {
      $this->valid_hash = false;
      return false;      
    } 
  }
  
  public function isValid(){
    $this->valid_date = $this->compareDate();
    $this->valid_hash = $this->compareHash();
    if($this->valid_date AND $this->valid_hash){
      $this->valid = true;
      return true;
    } else {
      $this->valid = false;
      return false;
    }
    
  }
  
}// END

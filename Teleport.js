#!/usr/bin/env node

/*
 * Teleport Bridge 
 * Copyright (c) Artrepreneur1
 * Use of this source code is governed by an MIT
 * license that can be found in the LICENSE file.
 * This is an implementation of a privacy bridging node. 
 * Currently, utilizes ECDSA Signatures to validate burning or vaulting of assets.
 * Signatures allow minting to occur cross chain. 
 */

const cors = require('cors');
var express = require('express');
var app = express();
var path = require('path');
global.fetch = require('node-fetch');
const util = require('util');
const exec = util.promisify(require('child_process').exec);
const { spawn } = require('child_process');
const os = require('os');
const { ethers } = require("ethers");
const fs = require("fs");
app.set('trust proxy', true);
app.use(cors());
const Web3 = require('web3');

/* Load Settings */
const settings = getSettings();

/* Settings Mapping */
const settingsMap = new Map();

for (i in settings){
     //Stucture: settingsMap.set('someLuxCoin', {chain1:'', ..., chainN: ''})
     settingsMap.set(i.toString(), settings[i]);
}

/* ABI's */
var teleportContractABI = require('./MultiTeleportBridge.json');

/* RPC list */
const rpcList = settingsMap.get('RPC');
const networkName = settingsMap.get('NetNames');

/* DB */
const DB = settingsMap.get('DB');

/* Signing MSG */
var msg = settingsMap.get('Msg');; //signing msg used in front running prevention

/* 
 * ECDSA PK  Using same PK for now. 
 * Requires MPC nodes to generate the PK
 */
const PK = settingsMap.get('Key').toString();

/* Bridge contracts for Teleport Bridge */
const list = settingsMap.get('Teleporter');

function getWeb3ForId(toNetId){
     return new Web3(new Web3.providers.HttpProvider(rpcList[toNetId]));
}

/* Given network id returns the appropriate contract to talk to as array of values */
function getNetworkAddresses(toNetId, tokenName){
     let arr = [];
     
     web3 = getWeb3ForId(toNetId);
     let chainName = networkName[toNetId];

     let tele = new web3.eth.Contract(teleportContractABI, list[chainName], {
          gasPrice: '20000000000' // default gas price in wei, 20 gwei in this case
     });

     arr.push(settingsMap.get(tokenName.toString())[chainName], web3, list[chainName], tele);
     return arr;
}

var Exp = /((^[0-9]+[a-z]+)|(^[a-z]+[0-9]+))+[0-9a-z]+$/i;

/* Database stuff */
var connStr = 'mongodb://teleportUser:'+DB+'@localhost:27017/Teleport';

var mongoose = require('mongoose'),
    Schema = mongoose.Schema;

mongoose.Promise = require('bluebird');
mongoose.connect(connStr, {
}, function (err) {
     if (err) throw err;
     console.log('Successfully connected to MongoDB');
});

app.get('/', function (req, res) {
     app.use(express.static(__dirname+'/views'));
     res.sendFile(path.join(__dirname,'./views/index.html'));
});

var port = process.env.PORT || 5000;
var server = app.listen(port, function () {
     var host = server.address().address;
     var port = server.address().port;
     console.log('>> Teleporter Running At:', host, port)
});

/* For multichain bridge */
var TeleportDataSchema = new Schema({
     txId: { type: String, required: false, index: { unique: true }, trim: true },
     chainType: { type: String, required: false, trim: true }, //from chain
     amount: { type: Number, required: false, default: 0},
     evmSenderAddress: { type: String, required: false, trim: true },
     sig: { type: String, required: true, index: { unique: true }, trim: true },
     hashedTxId: { type: String, required: false, index: { unique: true }, trim: true }
 });

var TeleportData = mongoose.model('TeleportData', TeleportDataSchema);

/*
 * Given a sig, checks TeleportData to see if sig already exists. 
 * Since there is only one valid sig for any txid + data combo, this sig is unique regardless of chain.
 * This is true because it is verified data, data we concat is oraclized against txid.
 * We don't have stealth sig for pkt to wpkt since it is a pegged asset, only evm to evm
 */
function checkStealthSig(evmTxHash2){
     console.log("Searching for txid:", evmTxHash2);
     return new Promise(async (resolve, reject) => { 
          try {
               TeleportData.findOne({
                    hashedTxId: evmTxHash2
               }, function (err, result) {
                    console.log("Find:", result, err);
                    if (err) throw err;
          
                    if (result && result != null) {
                         console.log('Entry already exists:', result);
                         resolve([true, result]);
                    }
                    else { // Not a replay
                         console.log('Entry does not exist');
                         resolve([false, result]);
                    }
               });
          }
          catch(e){
               console.log('Error:', e);
               reject([false]);
          }
     });
}


/*
 * Given parameters associated with the token burn, we validate and produce a signature entitling user to payout.
 * Parameters specific to where funds are being moved / minted to, are hashed, such that only the user has knowledge of
 * mint destination. Effectively, the transaction is teleported stealthily. 
 */
app.get('/api/v1/getsig/txid/:txid/fromNetId/:fromNetId/toNetIdHash/:toNetIdHash/tokenName/:tokenName/tokenAddrHash/:tokenAddrHash/msgSig/:msgSig/toTargetAddrHash/:toTargetAddrHash', function (req, res) { 
     
     /* Checking inputs */
     var stealthMode = true; // Stealth overrride by default, for now.
     var sig = 0;
     var evmTxHash2 = null;
     
     console.log('====================================================================');
     var evmTxHash = req.params.txid.trim();
     if (!(evmTxHash.length > 0) && !(evmTxHash.match(Exp))){
          res.send("NullTransactionError: bad transaction hash");
          return;
     }

     var fromNetId = req.params.fromNetId.trim();
     if (!fromNetId){
          res.send("NullFromNetIDError: No from netId sent.");
          return;
     }
     
     var toNetIdHash = req.params.toNetIdHash.trim();
     if (!toNetIdHash){
          res.send("NullToNetIDHashError: No to netId sent.");
          return;
     }

     var tokenName = req.params.tokenName.trim();
     if (!tokenName){
          res.send("NullTokenNameError: No token name sent.");
          return;
     }

     var tokenAddrHash = req.params.tokenAddrHash.trim();

     if (!tokenAddrHash){
          res.send("NullTokenAddressHashError: No token address hash sent.");
          return;
     }

     var toTargetAddrHash = req.params.toTargetAddrHash.trim();          
     if (!toTargetAddrHash){
          res.send("NullToTargetAddrHashError: No target address hash sent.");
          return;
     }
    
     var msgSig = req.params.msgSig.trim();
     if (!msgSig){
          res.send("NullMessageSignatureError: Challenge message signature not sent.");
          return;
     }

     console.log('EVM TX Hash:', evmTxHash, 'From NetId:', fromNetId, 'To NetId Hash:', toNetIdHash, 'Token Name:', tokenName, 'tokenAddrHash:', tokenAddrHash, 'toTargetAddrHash',toTargetAddrHash, 'msgSig:', msgSig);

     let fromNetArr = getNetworkAddresses(fromNetId, tokenName); 
     if (fromNetArr.length !== 4) {
          console.log("FromNetArrLengthError:", fromNetArr.length)
          res.send("Unknown error occurred.");
          return;
     }

     let frombridgeConAddr = fromNetArr[2];
     let fromTokenConAddr = fromNetArr[0]; 
     let w3From = fromNetArr[1];
     let fromBridgeContract = fromNetArr[3];
     let cnt = 0;
     
     /* Check that it's not a replay transaction */
     TeleportData.findOne({
          txId: evmTxHash // non stealth mode
     }, async function (err, result) {
          console.log("Find Result:", result, err);

          if (err) throw err;
          if (result && (result.length > 0)) {
               console.log('EntryAlreadyExistsError in teleport:', result);
               res.send(JSON.stringify({output: -1, tokenAmt: result.amount, signature: result.sig, hashedTxId: result.hashedTxId}));
               return;
          }

          else { // Not a replay
                    getEVMTx(evmTxHash, w3From, fromBridgeContract).then(async (transaction)=>{ //Get transaction details
                         if (transaction != null && transaction != undefined){
                              console.log('Transaction:', transaction);
                              let from = transaction.from; //Transaction Sender
                              let fromTokenContract = transaction.addressTo; //from token contract
                              let contract = transaction.contractTo; //from MultiTeleportBridge contract
                              let amt = transaction.value; 
                              let log = transaction.log;
                              let eventName = null;
                              let vault = null;

                              // Check that the logs we are looking for occurred
                              if (!log){
                                   res.send('NotVaultedOrBurnedError: No tokens were vaulted or burned.');
                                   return;
                              }
                              else{
                                   
                                   eventName = log;
                                   console.log('Event:', eventName);
                                   if (eventName.toString() === "BridgeBurned"){
                                        vault = false;
                                   }
                                   else if (eventName.toString() === "VaultDeposit"){
                                        vault = true;
                                   }
                              }
                              
                              // To prove user signed we recover signer for (msg, sig) using testSig which rtrns address which must == toTargetAddr or return error
                              var signerAddress = web3.eth.accounts.recover(msg, msgSig);//best  on server
                              console.log('signerAddress:', signerAddress.toString().toLowerCase(), 'From Address:', from.toString().toLowerCase());
                              
                              // Bad signer (test transaction signer must be same as burn transaction signer) => exit, front run attempt
                              let signerOk = false;
                              if (signerAddress.toString().toLowerCase() != from.toString().toLowerCase()){
                                   console.log("*** Possible front run attempt, message signer not transaction sender ***");
                                   res.send("NullToNetIDHashError: No to netId sent.");
                                   return;
                              }
                              else {
                                   signerOk = true;
                              }
                              
                              // If signerOk we use the toTargetAddrHash provided, else we hash the from address.
                              toTargetAddrHash = (signerOk) ? toTargetAddrHash : (Web3.utils.keccak256(from)); 

                              console.log('token contract:', fromTokenContract.toLowerCase(), 'fromTokenConAddr', fromTokenConAddr.toLowerCase(),'contract',  contract.toLowerCase(),'frombridgeConAddr', frombridgeConAddr.toLowerCase());
               
                              // Validate token and bridge contract addresses.
                              if (fromTokenContract.toLowerCase() === fromTokenConAddr.toLowerCase() && contract.toLowerCase() === frombridgeConAddr.toLowerCase()) { // Token was burned.
                                   let output ="";

                                   console.log('fromTokenConAddr', fromTokenConAddr,'tokenAddrHash', tokenAddrHash);

                                   //Produce signature for minting approval.
                                   try {
                                        //Signature confirms that coins were burned and user is entitled to redemption.
                                        if (stealthMode){ 
                                             evmTxHash2 = web3.utils.soliditySha3(evmTxHash);
                                             console.log("Stealth hashing",  evmTxHash2);

                                             sig = await hashAndSignTx(w3From.utils.toWei(amt.toString()), toTargetAddrHash, evmTxHash2, w3From, toNetIdHash, tokenAddrHash, vault.toString()); 
                                             console.log('Signature:', sig);
                                        }
                                        else {
                                             sig = await hashAndSignTx(w3From.utils.toWei(amt.toString()), toTargetAddrHash, evmTxHash, w3From, toNetIdHash, tokenAddrHash, vault.toString()); 
                                             console.log('Signature:', sig);
                                        }

                                        // Check for replays on stealth mode - using only the sig.
                                        if (stealthMode){
                                             var stealthFound = checkStealthSig(evmTxHash2); //see if saved already 
                                             console.log('stealthFound[1]',stealthFound[1]);
                                             if (stealthFound[0] && stealthFound[1]._doc) {
                                                  r = stealthFound[1]._doc;
                                                  sig = r.sig;
                                                  evmTxHash2 = r.hashedTxId;
                                                  cnt++;
                                                  console.log('Stealth transaction found...', cnt);
                                                  console.log(fromTokenContract, from, amt, sig, evmTxHash2);
                                                  res.send(JSON.stringify({fromTokenContractAddress: fromTokenContract, contract: contract, from: toTargetAddrHash, toNetIdHash: toNetIdHash, tokenAmt: amt, signature: sig, hashedTxId: evmTxHash2, tokenAddrHash: tokenAddrHash, vault: vault})); //output: -1, 
                                                  return;
                                             }
                                        
                                        }
                                        
                                        console.log("Saving info to DB:", evmTxHash, evmTxHash2, sig);
                                        
                                        //NOTE: For private transactions, store only the sig.
                                        var teleportData= new TeleportData;
                                        if (!stealthMode){
                                             teleportData.chainType = ct;
                                             teleportData.txId = evmTxHash;
                                             teleportData.amount = amt;
                                             teleportData.evmSenderAddress = from; //EVM sender address
                                        }
                                        
                                        else {
                                             teleportData.txId = evmTxHash2; //In stealth, txId is the hash
                                        }

                                        teleportData.hashedTxId = evmTxHash2;
                                        teleportData.sig = sig;//using signature

                                        // Input data into database and retrieve the new postId and date
                                        teleportData.save(function (err, result) {
                                             if (err) {
                                                  output = JSON.stringify({ Error: err});
                                                  console.log('Output:',output);
                                                  if (err.code == 11000){
                                                       if (!stealthMode){
                                                            output = JSON.stringify({fromTokenContractAddress: fromTokenContract, contract: contract, from: toTargetAddrHash, tokenAmt: amt, signature: sig, hashedTxId: evmTxHash, tokenAddrHash: tokenAddrHash, vault: vault}); // contractAddress, toChainID vault.toString()
                                                       }
                                                       else {
                                                            output = JSON.stringify({fromTokenContractAddress: fromTokenContract, contract: contract, from: toTargetAddrHash, tokenAmt: amt, signature: sig, hashedTxId: evmTxHash2, tokenAddrHash: tokenAddrHash, vault: vault});
                                                       }     
                                                  }
                                                  res.send(output);
                                                  return;
                                             }
                                             if (result) {
                                                  if (!stealthMode){
                                                       output = JSON.stringify({fromTokenContractAddress: fromTokenContract, contract: contract, from: toTargetAddrHash, tokenAmt: amt, signature: sig, hashedTxId: evmTxHash, tokenAddrHash: tokenAddrHash, vault: vault});
                                                  }
                                                  else {
                                                       output = JSON.stringify({fromTokenContractAddress: fromTokenContract, contract: contract, from: toTargetAddrHash, tokenAmt: amt, signature: sig, hashedTxId: evmTxHash2, tokenAddrHash: tokenAddrHash, vault: vault});
                                                  }
                                                  console.log(output);
                                                  res.send(output);
                                                  return;
                                             }
                                        });
                                   }

                                   catch (e) {
                                        if (e==="AlreadyMintedError"){
                                             output = JSON.stringify({ Error: e});
                                             console.log("AlreadyMintedError:", e);
                                        }
                                        else if (e==="GasTooLowError"){
                                             output = JSON.stringify({ Error: e});
                                             console.log("GasTooLowError:", e);
                                        }
                                        else {
                                             output = JSON.stringify({ Error: e});
                                             console.log("OtherError:", e);
                                        }
                                        res.send(output);
                                        return;
                                   }
                              }
                              else{
                                   output = JSON.stringify({ Error: "ContractMisMatchError: bad token or bridge contract address."})
                                   res.send(output);
                                   return;
                              }
                         }
                         else{
                              output = JSON.stringify({ Error: "NullTransactionError: bad transaction hash, no transaction on chain"})
                              res.send(output);
                              return;
                         }
                    });
          }
     });
});


function concatMsg(amt, targetAddressHash, txid, toContractAddress, toChainIdHash, vault){ 
     return amt+targetAddressHash+txid+toContractAddress+toChainIdHash+vault;
}

/* 
 * Settings retrieval
 */
function getSettings(){
     const data = fs.readFileSync('./Settings.json',
              {encoding:'utf8', flag:'r'});
     obj = JSON.parse(data);
     return obj;  
}

function findSetting(name, obj){
     let objVal = obj[name];
     return objVal;
}

/* return signed hashed transaction info */
function hashAndSignTx(amt, toTargetAddrHash, txid, web3, toChainIdHash, toContractAddress, vault){
     return new Promise(async (resolve, reject) => {
          try{

               console.log('Hashing:', 'To Wei Amount:',amt, 'txid:', txid, 'To Chain ID:', toChainIdHash , 'Contract Address:', toContractAddress, 'Vault:', vault);
               var message = concatMsg(amt, toTargetAddrHash, txid, toContractAddress, toChainIdHash, vault); 
               console.log('Message:', message);
               var hash = web3.utils.soliditySha3(message);
               console.log('Hash:', hash);
               var sig = await signMsg(hash, web3);
               console.log('MPC Address:', web3.eth.accounts.recover(hash, sig));
               resolve(sig);
          }
          catch(err){
               console.log(err);
               reject(0);
          }
     });
}

async function signMsg(message, web3){ //will become MPC
     let flatSig = await web3.eth.accounts.sign(message, PK);

     console.log('Flat Sig:',flatSig.signature);
     addr = ethers.utils.recoverAddress(flatSig.messageHash, flatSig.signature);
     console.log(addr);
     console.log('v:', flatSig.v, 'r:', flatSig.r, 's:', flatSig.s, 'hash:', flatSig.messageHash,'\n');
     return flatSig.signature;
}

/*
 * Given evmTxHash returns transaction details if transaction is valid and was sent to the correct smart contract address
 * For multichain transactions
 */
async function getEVMTx(txh, w3From, fromBridgeContract){
     console.log('In getEVMTx', 'txh:', txh);
     try {
          txh = txh.toString();
          let transaction = await w3From.eth.getTransaction(txh);
          let transactionReceipt = await w3From.eth.getTransactionReceipt(txh);
          console.log('GetEVMTransaction:', transaction);
          

          if (transaction != null && transactionReceipt != null && transaction != undefined && transactionReceipt != undefined ){
               console.log('Transaction:',transaction, 'Transaction Receipt:', transactionReceipt);
               transaction = Object.assign(transaction, transactionReceipt);
               var addrTo = transactionReceipt.logs[0].address; 
               var tokenAmt = (parseInt(transaction.input.slice(74,138), 16) / (10**18));
               tokenAmt -= (tokenAmt * .008);
               var contractTo = transaction.to;
               var from = transaction.from;
               var amount;

               let abi = [ "event BridgeBurned(address caller, uint256 amt)", "event VaultDeposit(address depositor, uint256 amt)" ];
               let iface = new ethers.utils.Interface(abi);
               let eventLog = transaction.logs;
               var log = null;
               console.log("Log Length:", eventLog.length);
               for (i = 0;  i < eventLog.length; i++){
                    try {
                         log = iface.parseLog(transaction.logs[i]); 
                         console.log('log', log.name);   
                         log = log.name;
    
                    } catch (error) {
                         console.log("EventNotFoundError in log number:", i);
                    }
                   
               }
               
               if (transactionReceipt.logs[0].data == '0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'){
                    amount = 0;
               }

               else {
                    amount = Number(transactionReceipt.logs[0].data);
               }
               amount =  w3From.utils.fromWei((amount.toLocaleString('fullwide', {useGrouping:false})).toString());
               console.log("Transaction to (Smart Contract):",contractTo);
               console.log("Transaction from:", from);
               console.log("Transaction to (Address):", addrTo);
               var transactionObj = JSON.parse('{"contractTo":"'+ contractTo +'", "addressTo":"'+ addrTo +'","from":"'+ from +'","tokenAmount":"'+ tokenAmt +'", "log":"'+ log +'", "value":"'+ amount +'"}');
               console.log('TransactionObj:',transactionObj);
               return transactionObj;
          }
          else {
               error2 = "TransactionRetrievalError: Failed to retrieve transaction. Check transaction hash is correct.";
               console.log('Error:', error2);
               return null;
          }

     } catch (error) {
          console.log('getEVMTxError:', error);
          return null;
     }
}



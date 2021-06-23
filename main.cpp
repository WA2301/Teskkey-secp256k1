#include <iostream>
#include <iomanip>

#include <key.h>
#include <pubkey.h>
#include <keystore.h>
#include <uint256.h>
#include <script/standard.h>
#include <script/script.h>
#include <script/ismine.h>
#include <base58.h>
#include <netaddress.h>
#include <protocol.h>
#include <base58.h>
#include <chainparams.h>
#include <stdio.h>
#include "secp256k1/include/secp256k1.h"

#define    COLOR_NONE                 "\033[0m"
#define    FONT_COLOR_RED             "\033[0;31m"
#define    FONT_COLOR_GREEN           "\033[0;32m"

/**
  0.P2PK
 
scriptPubKey[asm]: <pubkey> OP_CHECKSIG
scriptPubkey[hex]: 2102a5613bd857b7048924264d1e70e08fb2a7e6527d32b7ab1bb993ac59964ff397ac

scriptSig	[asm]: <sig>
scriptSig	[hex]: 3045022100ae3b4e589dfc9d48cb82d41008dc5fa6a86f94d5c54f9935531924602730ab8002202f88cf464414c4ed9fa11b773c5ee944f66e9b05cc1e51d97abc22ce098937ea

	4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b - Coinbase transaction in the genesis block. (3rd January 2009)
	f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16 - The first ever bitcoin transaction from Satoshi to Hal Finney actually used P2PK (Block 170, 12th January 2009)



1.P2PKH 
Address		[asm]: 0x00{20-byte keyhash} <chk>										//Start with prefix 1.
Address		[b58]: 1AtWkdmfmYkErU16d3KYykJUbEp9MAj9Sb

scriptPubKey[asm]: OP_DUP OP_HASH160 <PubKeyHash> OP_EQUALVERIFY OP_CHECKSIG
scriptPubKey[hex]: 76a9148fd139bb39ced713f231c58a4d07bf6954d1c20188ac

scriptSig	[asm]: <sig> <pubkey>
scriptSig	[hex]: 304502207fa7a6d1e0ee81132a269ad84e68d695483745cde8b541e3bf630749894e342a022100c1f7ab20e13e22fb95281a870f3dcf38d782e53023ee313d741ad0cfbc0c509001
				   03b0da749730dc9b4b1f4a14d6902877a92541f5368778853d9c4a0cb7802dcfb2


	6f7cf9580f1c2dfb3c4d5d043cdbb128c640e3f20161245aa7372e9666168516 - First P2PKH Transaction (16th January 2009)
	a1075db55d416d3ca199f55b6084e2115b9345e16c5cf302fc80e9d5fbf5d48d - Pizza Transaction (10,000 BTC)




2.P2WPKH
Address		[asm]: bc1 {20-byte keyhash} <chk>
Address		[b32]: bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4

scriptPubKey[asm]: 0 <PubKeyHash>
scriptPubkey[hex]: 0014751e76e8199196d454941c45d1b3a323f1433bd6

scriptSig		 : (empty)

witness		[asm]: <sig> <pubkey>
witness		[hex]: 








对于付款人支持，而收款人不支持隔离见证的只能使用普通地址 (P2PKH，P2SH) , 这不是废话？

4.P2SH-P2WPKH
Address		[asm]:				//with prefix 3.
Address		[hex]:

scriptPubKey[asm]: OP_HASH160 <20-byte-redeemScript-hash> OP_EQUAL	//redeemScript = 0 <PubKeyHash>  即前面的P2WPKH的scriptPubkey 
scriptPubkey[hex]: a914c596906f342478ca56707f7bb1bda659cb3cef9887

scriptSig	[asm]: 0x160014{20-byte-key-hash}
scriptSig	[hex]: 

witness		[asm]: <signature> <pubkey>






5.P2SH-P2WSH		//可适用付款人不支持，收款人支持隔离见证
Address		:			
scriptPubKey: 0xA914{20-byte-redeemScript-hash}87			//HASH160 <20-byte-redeemScript-hash> EQUAL
scriptSig	: 0x220020{32-byte-hash}
witness		: 0 <signature1> <1 <pubkey1> <pubkey2> 2 CHECKMULTISIG>





	1. witnessScript
	2. scripthash   = SHA256(witnessScript)
	3. redeemScript = 0x0020{32-byte scripthash}
	4. scriptPubKey = OP_HASH160 hash160(redeemScript) OP_EQUAL
						0xA914{ 20-byte-hash }87 //BIP 141
	5. with prefix 3.









3.P2WSH
Address		[asm]: bc1 {32-byte-scripthash} <chk>
Address		[b32]: 

scriptPubKey[asm]: 0 <ScriptHash> 				//SHA256
scriptPubkey[hex]: 

scriptSig		 : (empty)
witness		[asm]: 0 <signature1> <1 <pubkey1> <pubkey2> 2 CHECKMULTISIG>
witness		[hex]: 

 
 **/


/**
 * 测试密钥对
 * 私钥：9a9a6539856be209b8ea2adbd155c0919646d108515b60b7b13d6a79f1ae5174
 * 公钥：0340a609475afa1f9a784cad0db5d5ba7dbaab2147a5d7b9bbde4d1334a0e40a5e
 */ 
std::vector<unsigned char> TestPriKey = {
										0x9a, 0x9a, 0x65, 0x39, 0x85, 0x6b, 0xe2, 0x09,
										0xb8, 0xea, 0x2a, 0xdb, 0xd1, 0x55, 0xc0, 0x91,
										0x96, 0x46, 0xd1, 0x08, 0x51, 0x5b, 0x60, 0xb7,
										0xb1, 0x3d, 0x6a, 0x79, 0xf1, 0xae, 0x51, 0x74
										};


// 返回16进制字符代表的整数值
int hex2int(unsigned char x){
	if(x >= '0' && x <= '9'){
		return (x - '0');
	}
	if(x >= 'A' && x <= 'F'){
		return (x - 'A' + 10);
	}
	if(x >= 'a' && x <= 'f'){
		return (x - 'a' + 10);
	}
    return -1;
}

// 打印容器
template<typename T1>
void print(const char* str,const T1 pos, int size){
	unsigned char *begin = (unsigned char*)&pos[0];
	std::cout<<str;
	for(int ii = 0; ii < size; ii++){
		std::cout<<std::setw(2);
		std::cout<<std::setfill('0')<<std::hex<<(int)(*(begin + ii));
	}
	std::cout<<std::endl;
} 

 void show_prikey_WIF(unsigned char * prikey,bool compressed)
 {
	 int len = 0;
	 if(compressed)
	 {
		 len = 38;
	 }
	 else
	 {
		 len = 37;
	 }
	 

	unsigned char wif[len];	

	std::string net = Params().NetworkIDString();
	if(net.compare("main")==0)
	{
		wif[0] = 0x80;//主网：0x80，          另：LTC 为 0xb0   Dogecoin:9e
	}
	else if(net.compare("test")==0)
	{
		wif[0] = 0xEF;//测试：0xEF      
	}
		


	if(compressed)
	{
		wif[33] = 0x01;//压缩：01,不压缩：无
	}

	memcpy(wif+1,prikey,32);
	// print("  Add         version: ",wif,len-4);

	CSHA256 sha256;		
	unsigned char bytes256[32];

	//计算校验
	sha256.Reset().Write(wif,len-4).Finalize(bytes256);
	// print("  SHA-256              : ",bytes256,sizeof(bytes256));
	
	sha256.Reset().Write(bytes256,32).Finalize(bytes256);
	// print("  SHA-256 double       : ",bytes256,sizeof(bytes256));
	// print("  Get check code       : ",bytes256,4);

	memcpy(wif+len -4,bytes256,4);
	// print("  WIF key in hex     : ",wif,sizeof(wif));

	std::string str = EncodeBase58(wif,wif+len);
	std::cout<<"WIF                 key: "<<str<<std::endl;
 }


	
	CPubKey pubKey;

template <typename T>
CKeyID create_pubkey(const T pbegin, const T pend) {
	unsigned char prikey[32];
    int len = sizeof(prikey);
    int ii;                             // 索引值
    int ret;                            // 返回值

    unsigned char pubkeybytes[65];          // 公钥存储
    size_t clen;                        // 返回公钥长度

    secp256k1_context *secp256k1_context_sign;
    secp256k1_pubkey pubkey;            // secp256k1返回公钥

	std::vector<unsigned char>::iterator it = TestPriKey.begin();
	memcpy(prikey,&it[0],32);

    // 打印私钥
	// print("Private             key: " FONT_COLOR_RED,prikey,len);
	// printf(COLOR_NONE);

	//WIF格式：
	show_prikey_WIF(prikey,true);//


    // 生成公钥
    secp256k1_context_sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    ret = secp256k1_ec_pubkey_create(secp256k1_context_sign, &pubkey, prikey);  
    
    // 打印公钥
    if(ret){

        // printf("Public              key: ");
        // for(ii = 63; ii >= 32; ii--){
    	//     printf("%02x", pubkey.data[ii]);
        // }
        // printf(":");
        // for(ii = 31; ii >= 0; ii--){
        //     printf("%02x", pubkey.data[ii]);
        // }
		// printf("\n");

        // 获取非压缩公钥
        clen = 65;
        secp256k1_ec_pubkey_serialize(secp256k1_context_sign, pubkeybytes, &clen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
		// print("Uncompressed        key: ",pubkeybytes,clen);


        // 获取压缩公钥
        clen = 65;
        secp256k1_ec_pubkey_serialize(secp256k1_context_sign, pubkeybytes, &clen, &pubkey, SECP256K1_EC_COMPRESSED);

		// print("Compressed          key: " FONT_COLOR_GREEN,pubkeybytes,clen);
		printf(COLOR_NONE);

		
    }

    if (secp256k1_context_sign) {
        secp256k1_context_destroy(secp256k1_context_sign);
    }



	CSHA256 sha256;
	unsigned char bytes256[32];

	//调试用，直接写入公钥
	// unsigned char test[] = "0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";

	// for(int i = 0; i < 33; i++){		
    //     pubkeybytes[i] = hex2int(test[i*2]) * 16 + hex2int(test[i*2 + 1]);
    // }



	pubKey.Set(pubkeybytes,pubkeybytes+33);

	//1.计算公钥 SHA-256
	sha256.Reset().Write(pubkeybytes,33).Finalize(bytes256);
	// print("SHA-256                : ",bytes256,sizeof(bytes256));

	//2.计算SHA-256 + RIPEMD-160
	CKeyID pubkeyID = pubKey.GetID(); //WA2301: (SHA-256 + RIPEMD-160) ,先算sha-256,再算ripemd-160
	// print("Pubkey ID(.+RIPEMD-160): " FONT_COLOR_GREEN,pubkeyID.begin(),pubkeyID.size()); 
	// printf(COLOR_NONE);

    return pubkeyID;
}



//1.P2PKH
int create_P2PKH_address(const CKeyID &pubkeyID){

	// std::cout<<std::endl<<FONT_COLOR_RED<<"1.P2PKH :"<<COLOR_NONE<<std::endl;
 
	std::string destPubKey = EncodeDestination(pubkeyID);
	std::cout<<"P2PKH           Address: " FONT_COLOR_GREEN<<destPubKey<<COLOR_NONE<<std::endl;

	//Generate scriptPubkey
	// if(IsValidDestinationString(destPubKey)){
	// 	CTxDestination ctxDest = DecodeDestination(destPubKey);
	// 	CScript scriptPubkey = GetScriptForDestination(ctxDest);
		
	// 	std::cout<<"P2PKH      scriptPubkey: " FONT_COLOR_GREEN;	
	// 	print("",scriptPubkey.begin(),scriptPubkey.size());
	// 	std::cout<<COLOR_NONE<<std::endl;
	// }

	return 0;
}


//2.P2WPKH Segwit(bech32) address  !!! Bitcoin core 客户端默认地址为此类型(隔离) 
int create_P2WPKH_address(const CKeyID &pubkeyID){

	// std::cout<<FONT_COLOR_RED<<"2.P2WPKH :[core]"<<COLOR_NONE<<std::endl;	
	//打印bech32格式地址
	std::string bech32P2WPKH = EncodeDestination(WitnessV0KeyHash(pubkeyID));
	std::cout<<"P2WPKH          Address: " FONT_COLOR_GREEN<<bech32P2WPKH<<COLOR_NONE<<std::endl; 
	
	//Generate scriptPubkey
	// if(IsValidDestinationString(bech32P2WPKH)){
	// 	CTxDestination ctxDest = DecodeDestination(bech32P2WPKH);
	// 	CScript scriptPubkey = GetScriptForDestination(ctxDest);
		
	// 	std::cout<<"P2WPKH     scriptPubkey: " FONT_COLOR_GREEN;	
	// 	print("",scriptPubkey.begin(),scriptPubkey.size());
	// 	std::cout<<COLOR_NONE<<std::endl;
	// }

	return 0;
}



//3.P2SH(P2WPKH) 
//P2SH address，经官方wiki验证，此为P2SH地址; Bitcoin core 客户端默认地址为此类型（非隔离）
//另 Litecoin core 官方生成地址为此类地址，其中主版本号由05 改为 0x32					//全称： P2SH-P2WPKH，经验证，此为P2SH嵌套类
int create_P2SH_P2WPKH_address(const CKeyID &pubkeyID){

	// std::cout<<FONT_COLOR_RED<<"3.P2WPKH nested in P2SH :[core]"<<COLOR_NONE<<std::endl;

	//p2sh: 0014+pubkeyID
	CScript script = GetScriptForDestination(WitnessV0KeyHash(pubkeyID)); //fuck:::: WitnessV0KeyHash 表示隔离地址，只不过此为嵌套地址，所以最终为P2SH地址，最终为base58
	
	// print("Script(0014+Pubkey ID) : ",script,script.size());


	//WA2301: fuck!!! 等效代码：const CTxDestination& dest = p2sh;，CTxDestination会调用 CScriptID 构造函数，见standard.cpp
	//但是，CTxDestination 对应众多类型，为什么单单调用 CScriptID的构造函数？？ 应该是传入参数p2sh的类型决定的
	std::string destP2SH = EncodeDestination(script);
	std::cout<<"P2SH(P2WPKH)    Address: " FONT_COLOR_GREEN<<destP2SH<<COLOR_NONE<<std::endl;
	

	//Generate scriptPubkey
	// if(IsValidDestinationString(destP2SH)){
	// 	CTxDestination ctxDest = DecodeDestination(destP2SH);
	// 	CScript scriptPubkey = GetScriptForDestination(ctxDest);
		
	// 	std::cout<<"P2SH(P2WPKH)scriptPbkey: " FONT_COLOR_GREEN;	
	// 	print("",scriptPubkey.begin(),scriptPubkey.size());
	// 	std::cout<<COLOR_NONE<<std::endl;
	// }



	return 0;
}
 

// P2WSH(1-of-1 multisig):
// 4.P2WSH WA2301: 经过 https://iancoleman.io/bip39/ 验证通过 
int create_P2WSH_address(const CPubKey pbKey){                  //全称：非P2SH-P2WSH

	std::cout<<FONT_COLOR_RED<<"4.P2WSH(1-of-1 multisig) :"<<COLOR_NONE<<std::endl;

	/** 生成一个多签名脚本 */
	CScript mnScript = GetScriptForMultisig(1, {CPubKey(pbKey)});	//WA2301:解锁需求数量为1，签名个数为1个，若多个，则逗号隔开
	
	print("mnScript(xx+Pubkey+xx) : ",mnScript,mnScript.size());

	uint256 hash;
    CSHA256().Write(&mnScript[0], mnScript.size()).Finalize(hash.begin());
	print("  SAH-256              : ",hash.begin(),hash.size());
	
	std::string bech32P2WSH = EncodeDestination(WitnessV0ScriptHash(hash));
	std::cout<<"P2WSH           Address: " FONT_COLOR_GREEN<<bech32P2WSH<<COLOR_NONE<<std::endl;


	//Generate scriptPubkey
	if(IsValidDestinationString(bech32P2WSH)){
		CTxDestination ctxDest = DecodeDestination(bech32P2WSH);
		CScript scriptPubkey = GetScriptForDestination(ctxDest);
		
		std::cout<<"P2WSH      scriptPubkey: " FONT_COLOR_GREEN;	
		print("",scriptPubkey.begin(),scriptPubkey.size());
		std::cout<<COLOR_NONE<<std::endl;
	}

	return 0;
}

// 5.P2WSH nested in P2SH(1-of-1 multisig)：
// WA2301: 经过验证 https://iancoleman.io/bip39/
int create_P2SH_P2WSH_address(const CPubKey pbKey){

	std::cout<<FONT_COLOR_RED<<"5.P2WSH nested in P2SH (1-of-1 multisig) :"<<COLOR_NONE<<std::endl;

	/** 生成一个多签名脚本 */
	CScript mnScript = GetScriptForMultisig(1, {CPubKey(pbKey)});	//WA2301:解锁需求数量为1，签名个数为1个，若多个，则逗号隔开
	
	print("mnScript(xx+Pubkey+xx) : ",mnScript,mnScript.size());

	uint256 hash;
    CSHA256().Write(&mnScript[0], mnScript.size()).Finalize(hash.begin());

	CScript script = GetScriptForDestination(WitnessV0ScriptHash(hash));

	std::string destP2SH = EncodeDestination(script);
	std::cout<<"P2SH(P2WSH)     Address: " FONT_COLOR_GREEN<<destP2SH<<COLOR_NONE<<std::endl;
	
	//Generate scriptPubkey
	if(IsValidDestinationString(destP2SH)){
		CTxDestination ctxDest = DecodeDestination(destP2SH);
		CScript scriptPubkey = GetScriptForDestination(ctxDest);
		
		std::cout<<"P2SH(P2WSH)scriptPubkey: " FONT_COLOR_GREEN;	
		print("",scriptPubkey.begin(),scriptPubkey.size());
		std::cout<<COLOR_NONE<<std::endl;
	}

	return 0;
}







//genAddress -mainnet -key=6d1b45dda1cda6e1310a0b43f17fb81e4315bf9e9b633bb2465f7e56b0f659f3
int main(int argc, char** argv){

	unsigned char _key[]="-key=";
	unsigned char *p_key;
	if( argc == 3 && strlen(argv[2]) < 70 )
	{
		if(memcmp(_key,argv[2],5) == 0)
		{
			p_key = (unsigned char*)argv[2]+5;
		}
		else
		{
			printf("Error:para 2 is wrong\n");
			return 0;
		}

		std::vector<unsigned char> data;
		if(DecodeBase58Check((const char*)p_key,data)) //wif
		{
			std::vector<unsigned char>::iterator it = TestPriKey.begin();		
			
			for(int i = 0; i < 32; i++)
			{		
				*(it+i) = *(data.begin()+i+1);
			}
			
		}
		else	//hex
		{
			if(strlen((const char*)p_key)!=64)
			{
				printf("Lenth is wrong:%d\n",(int)strlen((const char*)p_key));
				return 0;
			}

			for(int i=0;i<64;i++)
			{
				if((p_key[i]>='0' && p_key[i]<='9') || (p_key[i]>='a' && p_key[i]<='f'))
				{
					continue;
				}
				printf("The [%d] char is illegal:%c\r\n",i+1,p_key[i]);
				return 0;
			}

			std::vector<unsigned char>::iterator it = TestPriKey.begin();
			for(int i = 0; i < 32; i++){		
				*(it+i) = hex2int(p_key[i*2]) * 16 + hex2int(p_key[i*2 + 1]);
			}
		}
	}
	// else
	// {
	// 	printf("Error:num of para is wrong\n");
	// 	return 0;
	// }

	SelectParams(CBaseChainParams::MAIN);
	// if( strcmp(argv[1],"-testnet") == 0 )
	// {
	// 	// 选择测试网
	// 	SelectParams(CBaseChainParams::TESTNET);
	// 	printf("\n");
	// 	printf("-----------------------------------------------------------------------------------------\n");
	// 	printf("--                                       Testnet                                       --\n");
	// 	printf("-----------------------------------------------------------------------------------------\n");
	// }
	// else if( strcmp(argv[1],"-mainnet") == 0 )
	// {
	// 	// 选择主网
	// 	SelectParams(CBaseChainParams::MAIN);
	// 	printf("\n");
	// 	printf("*****************************************************************************************\n");
	// 	printf("**                                       Main                                          **\n");
	// 	printf("*****************************************************************************************\n");
	// }
	// else
	// {
	// 	printf("Error:net is wrong\n");
	// 	return 0;
	// }
	






	//Step 1. create public key
	CKeyID pubkeyID = create_pubkey(TestPriKey.begin(),TestPriKey.end());


	//Step 2.
	if( strcmp(argv[1],"-p2pkh") == 0 )
	{	
		create_P2PKH_address(pubkeyID);
	}
	else if( strcmp(argv[1],"-p2wpkh") == 0 )
	{

		create_P2WPKH_address(pubkeyID);//经客户端core验证通过！
	}
	else if( strcmp(argv[1],"-p2sh-p2wpkh") == 0 )
	{
		create_P2SH_P2WPKH_address(pubkeyID);	//经客户端core验证通过！
	}
	else
	{
		printf("Error:para 1 is wrong\n");
	}
	
	// create_P2WSH_address(pubKey);		//验证通过！

	// create_P2SH_P2WSH_address(pubKey);  //验证通过！
	




	// Sig_Ver();
	
	return 0;
}




// int Sig_Ver(void)
// {
 
// 	CKey priKey;
// 	//priKey.MakeNewKey(true);
// 	ECCVerifyHandle eccVerifyHandle ;
// 	ECC_Start();
// 	// 设置私钥数据 
// 	priKey.Set(TestPriKey.begin(), TestPriKey.end(), true);	
	
	
// 	printf("\n");
// 	// 检测公私钥是否匹配 
// 	if(priKey.VerifyPubKey(pubKey)){
// 		std::cout<<"***** Private Key vs. Public Key Match. *****";
// 	}
// 	printf("\n");



// 	// 获取公钥哈希值 
// 	uint256 hash = pubKey.GetHash();
// 	print("Hash              :",hash.begin(),hash.size());


// 	std::vector<unsigned char> vchSig; 
// 	priKey.Sign(hash, vchSig);

// 	// 打印签名
// 	print("Sign              :",vchSig.begin(),vchSig.size());
	
	
// 	printf("\n");
// 	// 校验签名 
// 	if(pubKey.CheckLowS(vchSig) && pubKey.Verify(hash, vchSig)){
// 		std::cout<<"**** Public Key Verify Sign Ok. ****";
// 	}
// 	printf("\n");
// 	ECC_Stop();
// }

// #include <base58.h>

// #include <support/cleanse.h>

// #include <bech32.h>
// #include <hash.h>
// #include <script/script.h>
// #include <uint256.h>
// #include <utilstrencodings.h>
// #include <boost/variant/apply_visitor.hpp>
// #include <boost/variant/static_visitor.hpp>

// #include <algorithm>
// #include <assert.h>
// #include <string.h>


// #include <stdio.h>
// #include <iostream>
// #include <iomanip>

	// WA2301: bech32 解码
	// const std::string str = "bc1q5jkp7p9rzur293c4zmu0auhhzwuw65mms4y2muvhpem2tj67umqszyfaax";

    // auto bech = bech32::Decode(str);
	// std::vector<unsigned char> data;

    // if (bech.second.size() > 0 && bech.first == "bc") {
    //     // Bech32 decoding
    //     int version = bech.second[0]; // The first 5 bit symbol is the witness version (0-16)
    //     // The rest of the symbols are converted witness program bytes.
    //     if (ConvertBits<5, 8, false>(data, bech.second.begin() + 1, bech.second.end())) {
	// 		print("+++:",data.begin(),data.size());
    //     }
    // }

<?php

// パラメータ類
$client_id = 'c48f8432-12d7-4085-a850-78b93771de0a';
$client_secret = 'IOq8Q~uIXOisE2ZOvgVgj5AdgHzpY.hlNmUAGaTg';
$redirect_uri = 'https://OIDC-Azure-SN.azurewebsites.net/index.php';
$authorization_endpoint = 'https://login.microsoftonline.com/8c03d386-25d9-400e-b3e8-f35f76928ff4/oauth2/v2.0/authorize';
$token_endpoint = 'https://login.microsoftonline.com/8c03d386-25d9-400e-b3e8-f35f76928ff4/oauth2/v2.0/token';
$response_type = 'code';
$state =  'state_phpv1';

// codeの取得
$req_code = $_GET['code'];
if(!$req_code){
	// 初回アクセスなのでログインプロセス開始
	// session生成
	session_start();
	$_SESSION['nonce'] = md5(microtime() . mt_rand());
	// GETパラメータ関係
	$query = http_build_query(array(
		'client_id'=>$client_id,
		'response_type'=>$response_type,
		'redirect_uri'=> $redirect_uri,
		'scope'=>'openid email',
		'state'=>$state,
		'nonce'=>$_SESSION['nonce'],
		'prompt'=>'admin_consent'
	));
	// リクエスト
	header('Location: ' . $authorization_endpoint . '?' . $query );
	exit();
}

// sessionよりnonceの取得
session_start();
$nonce = $_SESSION['nonce'];

// POSTデータの作成
$postdata = array(
	'grant_type'=>'authorization_code',
	'client_id'=>$client_id,
	'code'=>$req_code,
	'client_secret'=>$client_secret,
	'redirect_uri'=>$redirect_uri
);

// TokenエンドポイントへPOST
$ch = curl_init($token_endpoint);
curl_setopt( $ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt( $ch, CURLOPT_POSTFIELDS, http_build_query($postdata));
curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
$response = json_decode(curl_exec($ch));
curl_close($ch);

// id_tokenの取り出しとdecode
$id_token = explode('.', $response->id_token);
$payload = base64_decode(str_pad(strtr($id_token[1], '-_', '+/'), strlen($id_token[1]) % 4, '=', STR_PAD_RIGHT));
$payload_json = json_decode($payload, true);

// 整形と表示
print<<<EOF
	<html>
	<head>
	<meta http-equiv='Content-Type' content='text/html; charset=utf-8' />
	<title>Obtained claims</title>
	</head>
	<body>
	<table border=1>
	<tr><th>Claim</th><th>Value</th></tr>
EOF;
	// nonceの検証
	if($payload_json['nonce']==$nonce){
		print('Verified / nonce : '.$payload_json['nonce'].'<BR>');
	}else{
		print('Not verified / nonce : '.$payload_json['nonce'].'<BR>');
	}
	// id_tokenの中身の表示
	foreach($payload_json as $key => $value){
		print('<tr><td>'.$key.'</td><td>'.$value.'</td></tr>');
	}
print<<<EOF
	</table>
	</body>
	</html>
EOF;

?>

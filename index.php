<?php

// パラメータ類
$client_id = '<アプリケーションIDを張り付けてください>';
$client_secret = '<キーを張り付けてください>';
$redirect_uri = 'https://<アプリケーション名を張り付けてください>.azurewebsites.net/index.php';
$authorization_endpoint = '<OAUTH 2.0 承認エンドポイントのアドレスを張り付けてください>';
$token_endpoint = '<OAUTH 2.0 トークンエンドポイントのアドレスを張り付けてください>';
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

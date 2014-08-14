﻿#include <stdio.h>

#include "swsds.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>

/**
 * 标准错误码定义
 * 根据错误码输出错误信息，并且打印调用函数传入的msg信息
 */
int print_error_msg(int ret, char *msg)
{
	if (NULL != msg)
		printf("%s \n", msg);
	switch (ret) {
	case SDR_UNKNOWERR:
		printf("未知错误\n");
		break;

	case SDR_NOTSUPPORT:
		printf("不支持\n");
		break;

	case SDR_COMMFAIL:
		printf("通信错误\n");
		break;

	case SDR_HARDFAIL:
		printf("硬件错误\n");
		break;

	case SDR_OPENDEVICE:
		printf("打开设备错误\n");
		break;

	case SDR_OPENSESSION:
		printf("打开会话句柄错误\n");
		break;

	case SDR_PARDENY:
		printf("权限不满足\n");
		break;

	case SDR_KEYNOTEXIST:
		printf("密钥不存在\n");
		break;

	case SDR_ALGNOTSUPPORT:
		printf("不支持的算法\n");
		break;

	case SDR_ALGMODNOTSUPPORT:
		printf("不支持的算法模式\n");
		break;

	case SDR_PKOPERR:
		printf("公钥运算错误\n");
		break;

	case SDR_SKOPERR:
		printf("私钥运算错误\n");
		break;

	case SDR_SIGNERR:
		printf("签名错误\n");
		break;

	case SDR_VERIFYERR:
		printf("验证错误\n");
		break;

	case SDR_SYMOPERR:
		printf("对称运算错误\n");
		break;

	case SDR_STEPERR:
		printf("步骤错误\n");
		break;

	case SDR_FILESIZEERR:
		printf("文件大小错误或输入数据长度非法\n");
		break;

	case SDR_FILENOEXIST:
		printf("文件不存在\n");
		break;

	case SDR_FILEOFSERR:
		printf("文件操作偏移量错误\n");
		break;

	case SDR_KEYTYPEERR:
		printf("密钥类型错误\n");
		break;

	case SDR_KEYERR:
		printf("密钥错误\n");
		break;

		/*扩展错误码*/
	case SWR_BASE:
		printf("自定义错误码基础值\n");
		break;

	case SWR_INVALID_USER:
		printf("无效的用户名\n");
		break;

	case SWR_INVALID_AUTHENCODE:
		printf("无效的授权码\n");
		break;

	case SWR_PROTOCOL_VER_ERR:
		printf("不支持的协议版本\n");
		break;

	case SWR_INVALID_COMMAND:
		printf("错误的命令字\n");
		break;

	case SWR_INVALID_PARAMETERS:
		printf("参数错误或错误的数据包格式\n");
		break;

	case SWR_FILE_ALREADY_EXIST:
		printf("已存在同名文件\n");
		break;

	case SWR_SYNCH_ERR:
		printf("多卡同步错误\n");
		break;

	case SWR_SYNCH_LOGIN_ERR:
		printf("多卡同步后登录错误\n");
		break;

	case SWR_SOCKET_TIMEOUT:
		printf("超时错误\n");
		break;

	case SWR_CONNECT_ERR:
		printf("连接服务器错误\n");
		break;

	case SWR_SET_SOCKOPT_ERR:
		printf("设置Socket参数错误\n");
		break;

	case SWR_SOCKET_SEND_ERR:
		printf("发送LOGINRequest错误\n");
		break;

	case SWR_SOCKET_RECV_ERR:
		printf("发送LOGINRequest错误\n");
		break;

	case SWR_SOCKET_RECV_0:
		printf("发送LOGINRequest错误\n");
		break;

	case SWR_SEM_TIMEOUT:
		printf("超时错误\n");
		break;

	case SWR_NO_AVAILABLE_HSM:
		printf("没有可用的加密机\n");
		break;

	case SWR_NO_AVAILABLE_CSM:
		printf("加密机内没有可用的加密模块\n");
		break;

	case SWR_CONFIG_ERR:
		printf("配置文件错误\n");
		break;

		/*密码卡错误码*/
	case SWR_CARD_BASE:
		printf("密码卡错误码\n");
		break;

	case SWR_CARD_UNKNOWERR:
		printf("未知错误\n");
		break;

	case SWR_CARD_NOTSUPPORT:
		printf("不支持的接口调用\n");
		break;

	case SWR_CARD_COMMFAIL:
		printf("与设备通信失败\n");
		break;

	case SWR_CARD_HARDFAIL:
		printf("运算模块无响应\n");
		break;

	case SWR_CARD_OPENDEVICE:
		printf("打开设备失败\n");
		break;

	case SWR_CARD_OPENSESSION:
		printf("创建会话失败\n");
		break;

	case SWR_CARD_PARDENY:
		printf("无私钥使用权限\n");
		break;

	case SWR_CARD_KEYNOTEXIST:
		printf("不存在的密钥调用\n");
		break;

	case SWR_CARD_ALGNOTSUPPORT:
		printf("不支持的算法调用\n");
		break;

	case SWR_CARD_ALGMODNOTSUPPORT:
		printf("不支持的算法调用\n");
		break;

	case SWR_CARD_PKOPERR:
		printf("公钥运算失败\n");
		break;

	case SWR_CARD_SKOPERR:
		printf("私钥运算失败\n");
		break;

	case SWR_CARD_SIGNERR:
		printf("签名运算失败\n");
		break;

	case SWR_CARD_VERIFYERR:
		printf("验证签名失败\n");
		break;

	case SWR_CARD_SYMOPERR:
		printf("对称算法运算失败\n");
		break;

	case SWR_CARD_STEPERR:
		printf("多步运算步骤错误\n");
		break;

	case SWR_CARD_FILESIZEERR:
		printf("文件长度超出限制\n");
		break;

	case SWR_CARD_FILENOEXIST:
		printf("指定的文件不存在\n");
		break;

	case SWR_CARD_FILEOFSERR:
		printf("文件起始位置错误\n");
		break;

	case SWR_CARD_KEYTYPEERR:
		printf("密钥类型错误\n");
		break;

	case SWR_CARD_KEYERR:
		printf("密钥错误\n");
		break;

	case SWR_CARD_BUFFER_TOO_SMALL:
		printf("接收参数的缓存区太小\n");
		break;

	case SWR_CARD_DATA_PAD:
		printf("数据没有按正确格式填充，或解密得到的脱密数据不符合填充格式\n");
		break;

	case SWR_CARD_DATA_SIZE:
		printf("明文或密文长度不符合相应的算法要求\n");
		break;

	case SWR_CARD_CRYPTO_NOT_INIT:
		printf("该错误表明没有为相应的算法调用初始化函数\n");
		break;

		//01/03/09版密码卡权限管理错误码
	case SWR_CARD_MANAGEMENT_DENY:
		printf("管理权限不满足\n");
		break;

	case SWR_CARD_OPERATION_DENY:
		printf("操作权限不满足\n");
		break;

	case SWR_CARD_DEVICE_STATUS_ERR:
		printf("当前设备状态不满足现有操作\n");
		break;

	case SWR_CARD_LOGIN_ERR:
		printf("登录失败\n");
		break;

	case SWR_CARD_USERID_ERR:
		printf("用户ID数目/号码错误\n");
		break;

	case SWR_CARD_PARAMENT_ERR:
		printf("参数错误\n");
		break;

		//05/06版密码卡权限管理错误码
	case SWR_CARD_MANAGEMENT_DENY_05:
		printf("管理权限不满足\n");
		break;

	case SWR_CARD_OPERATION_DENY_05:
		printf("操作权限不满足\n");
		break;

	case SWR_CARD_DEVICE_STATUS_ERR_05:
		printf("当前设备状态不满足现有操作\n");
		break;

	case SWR_CARD_LOGIN_ERR_05:
		printf("登录失败\n");
		break;

	case SWR_CARD_USERID_ERR_05:
		printf("用户ID数目/号码错误\n");
		break;

	case SWR_CARD_PARAMENT_ERR_05:
		printf("参数错误\n");
		break;

		/*读卡器错误*/
	case SWR_CARD_READER_BASE:
		printf("读卡器类型错误\n");
		break;

	case SWR_CARD_READER_PIN_ERROR:
		printf("口令错误\n");
		break;

	case SWR_CARD_READER_NO_CARD:
		printf("IC未插入\n");
		break;

	case SWR_CARD_READER_CARD_INSERT:
		printf("IC插入方向错误或不到位\n");
		break;

	case SWR_CARD_READER_CARD_INSERT_TYPE:
		printf("IC类型错误\n");
		break;
	default:
		printf("未知错误码--------\n");
		break;
	}
	printf("错误码 ----> %x,%d",ret, ret);
	return ret;
}


int main(int argc, char **argv)
{

	void *hSessionHandle;
	SGD_HANDLE hDeviceHandle; /*设备句柄    typedef void*    SGD_HANDLE;*/

	int ret;

	if(0 != (ret = SDF_OpenDevice(&hDeviceHandle)))
		print_error_msg(ret, "设备打开失败");

	if(0 != (ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle)))
		print_error_msg(ret, "建立会话句柄失败");


	unsigned int algorithm_id = SGD_SM2_3;  // 指定算法标识
	unsigned int key_len = 256;
	ECCrefPublicKey public_key;
	ECCrefPrivateKey private_key;

	if(0 != (ret = SDF_GenerateKeyPair_ECC(hSessionHandle, algorithm_id, key_len, &public_key, &private_key)))
	{
		print_error_msg(ret, "产生 ECC 密钥对失败");
	}

	unsigned char puc_old_data[9] = {'w', '3', 'd', 'r', 'w', '3', 'd', 'r', '0'}; // 需要加密的明文
	unsigned int puc_len_data = 8;
	ECCCipher enc_data; //加密之后的密文

	if(0 != (ret = SDF_ExternalEncrypt_ECC(hSessionHandle, algorithm_id, &public_key, puc_old_data, puc_len_data, &enc_data)))
	{
		print_error_msg(ret, "数据加密失败");
	}

	unsigned char puc_new_data[9] = {'0'}; //解密数据
	unsigned int new_len; // 解密得到的数据长度

	if(0 != (ret = SDF_ExternalDecrypt_ECC(hSessionHandle, algorithm_id, &private_key, &enc_data, puc_new_data, &new_len)))
	{
		print_error_msg(ret, "数据解密失败");
	}

	printf("puc_new_data-->  %s, %d", puc_new_data, new_len);


















	if(0 != (ret = SDF_CloseSession(hSessionHandle)))
		print_error_msg(ret, "关闭会话句柄失败");

	if(0 != (ret = SDF_CloseDevice(hDeviceHandle)))
		print_error_msg(ret, "关闭设备失败");





































	sleep(2);

	return 0;
}




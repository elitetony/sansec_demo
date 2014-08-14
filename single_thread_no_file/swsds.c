#include <stdio.h>

#include "swsds.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "test.h"

#define MAX_PTHREAD  (1024 * 3)

SGD_HANDLE hDeviceHandle; /*全局设备句柄    typedef void*    SGD_HANDLE;*/


//声明为外部变量以便于测试函数使用
void *hSessionHandle;
unsigned int algorithm_id = SGD_SM2_3;  // 指定算法标识
unsigned int key_len = 256;
ECCrefPublicKey public_key;
ECCrefPrivateKey private_key;



void *encrypt_func(void *argv);  // 对一个文件的加密线程



void *decrypt_func(void *argv);

int main(int argc, char **argv)
{
//	void *hSessionHandle;
	//open_device_and_session(&hDeviceHandle, &hSessionHandle);

	printf("%d \n", argc);
	if(argc <= 2)
	{
		printf("______argv erro \n");
		return -1;
	}

	char *num_ch = argv[1];
	int test_num = atoi(num_ch);

	printf("%s, %d \n",num_ch, test_num);

	struct _Head_File_Mutex *head = NULL;
	if(NULL == (head = init_head_file_mutex(test_num)))
	{
		printf("头节点初始化失败\n");
		return -1;
	}

	printf("-----------------\n");

	struct _List_File_Mutex *node = NULL; // 文件节点
	// 初始化test_num个明文文件，并加入链表结构
	int i;
	for(i = 1; i <= test_num; i++)
	{
//		printf("AAAAAAAAAAAAAAAAAAAAAAA\n");

		if(NULL == (node = make_test_file_and_init_list_file_mutex_node_and_ret(i)))  // 生成文件信息节点
		{
			printf("内存申请失败\n");
			return 0;
		}
//		printf("**************************\n");

		add_node_to_list(head, node);
	}




	int ret;
	if (SDR_OK != (ret = SDF_OpenDevice(&hDeviceHandle))) {
		print_error_msg(ret, "打开设备失败");
		return ret;
	}

	if (SDR_OK != (ret = SDF_OpenSession(hDeviceHandle, &hSessionHandle))) {
		print_error_msg(ret, "打开会话失败");
		return ret;
	}

	DEVICEINFO device_info;  // 获取设备信息
	if (SDR_OK != (ret = SDF_GetDeviceInfo(hSessionHandle, &device_info))) {
		print_error_msg(ret, "获取设备信息失败");
		return ret;
	}

	// 打印设备信息
	print_device_info(&device_info);

	//获取指定长度的随机数
	unsigned int random_length = 256;
	unsigned char random_out_buffer[16384] = {0}; // ?需要否
//	memset(random_out_buffer, 0, 16384);
	// 功能：获取随机数
	get_generate_random(hSessionHandle, random_length, random_out_buffer);

	PrintData("随机数:", random_out_buffer, random_length, 64);  //一行打印64个八进制数


//	unsigned int algorithm_id = SGD_SM2_3;  // 指定算法标识
//	unsigned int key_len = 256;
//	ECCrefPublicKey public_key;
//	ECCrefPrivateKey private_key;
//
//	struct timeval begin_time, stop_time;


	generate_key_pair_ecc(hSessionHandle, algorithm_id, key_len, &public_key, &private_key);

	save_key_pair_ecc(&public_key, &private_key); // 保存密钥对到文件

//	pid_t childpid;
//	childpid = fork();
//	if(0 == childpid)
//	{
//		// child process
//		gettimeofday(&begin_time, NULL);
//
//		external_file_data_encrypt_ecc(hSessionHandle, algorithm_id, &public_key, "test.txt", "ciphertext.txt");
//		gettimeofday(&stop_time, NULL);
//		printf("time ---> %d \n",stop_time.tv_usec - begin_time.tv_usec);
//	}
//	else if(-1 == childpid )
//	{
//		// parent error
//
//	}
//	else
//	{
//		// parent process
//		sleep(3);
//		gettimeofday(&begin_time, NULL);
//		external_file_data_decrypt_ecc(hSessionHandle, algorithm_id, &private_key, "te.txt", "ciphertext.txt");
//		gettimeofday(&stop_time, NULL);
//		printf("time ---> %d \n",stop_time.tv_usec - begin_time.tv_usec);
//	}


	//external_file_data_encrypt_ecc(hSessionHandle, algorithm_id, &public_key, "test.txt", "ciphertext.txt");

	//external_file_data_decrypt_ecc(hSessionHandle, algorithm_id, &private_key, "te.txt", "ciphertext.txt");


//	int status;
//	printf("等待子进程结束 \n");
//	wait(&status);

	//初始化file_mutex结构体
	/****测试代码  ***/
	/*******************
	extern struct _File_Mutex file_st1, file_st2, file_st3;
	init_file_mutex(&file_st1, "text1.txt", "cip1.txt", "text_1new.txt");
	init_file_mutex(&file_st2, "text2.txt", "cip2.txt", "text_2new.txt");
	init_file_mutex(&file_st3, "text3.txt", "cip3.txt", "text_3new.txt");

	pthread_t pid_encrypt_1, pid_encrypt_2, pid_encrypt_3;  // 三个文件的加密线程
	pthread_t pid_decrypt_1, pid_decrypt_2, pid_decrypt_3;  // 三个解密线程

	pthread_create(&pid_encrypt_1, NULL, encrypt_func, &file_st1); // 加密
	pthread_create(&pid_encrypt_2, NULL, encrypt_func, &file_st2); // 加密
	pthread_create(&pid_encrypt_3, NULL, encrypt_func, &file_st3); // 加密

	pthread_create(&pid_decrypt_1, NULL, decrypt_func, &file_st1); // 解密
	pthread_create(&pid_decrypt_2, NULL, decrypt_func, &file_st2); // 解密
	pthread_create(&pid_decrypt_3, NULL, decrypt_func, &file_st3); // 解密

    pthread_join(pid_encrypt_1,NULL);
    pthread_join(pid_encrypt_2,NULL);
    pthread_join(pid_encrypt_3,NULL);

    pthread_join(pid_decrypt_1,NULL);
    pthread_join(pid_decrypt_2,NULL);
    pthread_join(pid_decrypt_3,NULL);
    ***************************/

	/****测试代码  ***/
	pthread_t pid_encrypt[MAX_PTHREAD];  //MAX_PTHREAD 加密线程
	pthread_t pid_decrypt[MAX_PTHREAD];  //MAX_PTHREAD 解密线程

//	int j;
//	for(j = 0; j < test_num; i++)
//	{
//		struct _List_File_Mutex *node = NULL;
//		pthread_create(&pid_encrypt[j], NULL, encrypt_func, &file_st1); // 加密
//	}

	// 遍历链表

	// search_and_create_encrypt_pthread(struct _Head_File_Mutex *head, pthread_t *pid_encrypt)
	{

		struct _List_File_Mutex *temp = NULL;
		temp = head->next;
		struct _List_File_Mutex *index = NULL;
		index = head->next;
		int pid_num = 0;
		while(NULL != index)
		{
			pthread_create(&pid_encrypt[pid_num], NULL, encrypt_func, &(index->file_info)); // 加密
			index = temp->next;
			temp = index;
			pid_num++;
		}

	}
	int pid_num = 0;

	// search_and_create_decrypt_pthread(struct _Head_File_Mutex *head, pthread_t *pid_encrypt)
	{

		struct _List_File_Mutex *temp = head->next;
		struct _List_File_Mutex *index = head->next;
		int pid_num = 0;
		while(NULL != index)
		{
			pthread_create(&pid_decrypt[pid_num], NULL, decrypt_func, &(index->file_info)); // 加密
			index = temp->next;
			temp = index;
			pid_num++;
		}

	}

	int pid_i;
	for(pid_i = 0; i < test_num; pid_i++)
	{
	    pthread_join(pid_encrypt[pid_i],NULL);

	    pthread_join(pid_decrypt[pid_i],NULL);

	}


















	printf("=======对数据加密成功====\n");

	close_devices_and_session(hDeviceHandle, hSessionHandle);
	destroy_list(head);
	return 0;
}

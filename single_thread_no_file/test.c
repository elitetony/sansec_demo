#include "test.h"


struct _File_Mutex file_st1, file_st2, file_st3;

//struct _File_Mutex file_st1, file_st2, file_st3;

//初始化file_mutex结构体
int init_file_mutex(file_mutex *file_st, char *plaintext_old, char *file_ciphertext, char *plaintext_new)
{
	strcpy(&(file_st->file_plaintext_old), plaintext_old);
	strcpy(&(file_st->file_ciphertext), file_ciphertext);
	strcpy(&(file_st->file_plaintext_new), plaintext_new);

//	printf("init__%s, %s, %s \n",&(file_st->file_plaintext_old), &(file_st->file_ciphertext), &(file_st->file_plaintext_new));

//	file_st->lock_plaintext_old = PTHREAD_MUTEX_INITIALIZER;
//	file_st->lock_ciphertext = PTHREAD_MUTEX_INITIALIZER;
//	file_st->lock_plaintext_new = PTHREAD_MUTEX_INITIALIZER;

	pthread_mutex_init(&(file_st->lock_plaintext_old), NULL);
	pthread_mutex_init(&(file_st->lock_ciphertext), NULL);

	pthread_mutex_lock(&(file_st->lock_ciphertext)); //  给密码文件上锁，防止还没有输出密码文件时，解码线程开始运行.暂时这样处理，但是这样处理有些问题，需要采用pthread_cond_t来处理

	pthread_mutex_init(&(file_st->lock_plaintext_new), NULL);

	pthread_cond_init(&(file_st->cond_ciphertext), NULL);  // 暂时不用

	return 0;
}


//  初始化文件链表的头节点 num_node是需要测试的线程数(即解密和加密的文件数)
struct _Head_File_Mutex *init_head_file_mutex(int num_node)
{
	struct _Head_File_Mutex * head  = NULL;
	if( NULL == (head = (struct _Head_File_Mutex *)malloc(sizeof(struct _Head_File_Mutex))))
		return NULL;
	head->num_node = num_node;
	head->next = NULL;
	return head;
}

/**
 * 根据i的值来自动造生成i个原始明文文件,并且响应生成i个密文和i个解密文件的文件名字
 * 例如第100个加解密线程  使用的文件名依次是：100_old.txt, 100_cip.txt, 100_new.txt
 *
 * 生成一个文件信息节点，并返回节点指针
 */
struct _List_File_Mutex *make_test_file_and_init_list_file_mutex_node_and_ret(int i)
{
	struct _List_File_Mutex *node = NULL; // 文件节点
	if(NULL == (node = (struct _List_File_Mutex *)malloc(sizeof(struct _List_File_Mutex))))
		return NULL;

	node->next = NULL;
	//node->file_info

	char temp_old[64];
	char temp_cip[64];
	char temp_new[64];


	char command[512];

	sprintf(temp_old, "%d%s", i, "_old.txt"); // 原始明文文件名

	sprintf(command, "cp -r %s %s", "text.txt", temp_old);
	int ret;
	if(-1 == (ret = system(command)))
	{
		printf("原始明文拷贝失败 \n");
		return NULL;
	}

	sprintf(temp_cip, "%d%s", i, "_cip.txt"); // 加密的密文文件名
	sprintf(temp_new, "%d%s", i, "_new.txt"); // 解密密文得到的明文文件名


	init_file_mutex(&(node->file_info), temp_old, temp_cip, temp_new);

	return node;
}

/**
 * 头插法添加节点
 *
 */
int add_node_to_list(struct _Head_File_Mutex *head, struct _List_File_Mutex *node)
{
	node->next = head->next;
	head->next = node;
	return 0;
}

int destroy_list(struct _Head_File_Mutex *head)
{
	struct _List_File_Mutex *index = head->next;
	struct _List_File_Mutex *temp = head->next;
	while(NULL != temp)
	{
		free(temp);
		temp = index->next;
		index = temp;
	}
	free(head);
	return 0;
}



void *encrypt_func(void *argv)  // 对一个文件的加密线程
{
	struct _File_Mutex *temp_file = argv;

	pthread_mutex_lock(&(temp_file->lock_plaintext_old)); //取得明文文件的访问权限(加锁或阻塞)

	struct timeval begin_time, stop_time;
	gettimeofday(&begin_time, NULL);
	external_file_data_encrypt_ecc(hSessionHandle, algorithm_id, &public_key, temp_file->file_plaintext_old, temp_file->file_ciphertext);
	gettimeofday(&stop_time, NULL);
	printf("%s 文件加密用时: time ---> %d \n",temp_file->file_plaintext_old, stop_time.tv_usec - begin_time.tv_usec);
	pthread_mutex_unlock(&(temp_file->lock_ciphertext));   // 给密码文件解锁，使得解密进程开始运行
}



void *decrypt_func(void *argv)
{
	struct _File_Mutex *temp_file = argv;
	pthread_mutex_lock(&(temp_file->lock_ciphertext)); //给密码文件上锁
	struct timeval begin_time, stop_time;
	gettimeofday(&begin_time, NULL);
	external_file_data_decrypt_ecc(hSessionHandle, algorithm_id, &private_key, temp_file->file_plaintext_new, temp_file->file_ciphertext);
	gettimeofday(&stop_time, NULL);
	printf("%s 文件解密用时: time ---> %d \n",temp_file->file_ciphertext, stop_time.tv_usec - begin_time.tv_usec);
	pthread_mutex_unlock(&(temp_file->lock_plaintext_old));
}

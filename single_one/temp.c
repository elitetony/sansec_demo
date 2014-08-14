#include <stdio.h>

#include "swsds.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <pthread.h>
#include <stdlib.h>

/**
 * 根据i的值来自动造生成i个原始明文文件,并且响应生成i个密文和i个解密文件的文件名字
 * 例如第100个加解密线程  使用的文件名依次是：
 */
int make_test_file_and_init_list_file_mutex(int i)
{
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
		return -1;
	}
	
	
	sprintf(temp_cip, "%d%s", i, "_cip.txt"); // 加密的密文文件名
	
	sprintf(temp_new, "%d%s", i, "_new.txt"); // 解密密文得到的明文文件名

	printf("%s \n",temp_new);
	
	return 0;

}


int main(int argc, char **argv)
{
	int i = 428273;
	make_test_file_and_init_list_file_mutex(i);


	return 0;
}
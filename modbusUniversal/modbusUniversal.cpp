// modbusUniversal.cpp: определяет точку входа для консольного приложения.
//

#include "stdafx.h"
#include <conio.h>
#include "MUlib.h"


int main()
{
	/*tests*/
	
	ModUNI *mu = new ModUNI("127.0.0.1"/*remote device*/, 502/*remote dev. port*/, 50/*timeout milli secs*/);//TCP
	/*ModUNI *mu = new ModUNI("127.0.0.1", 502, 50,true);//RTU via TCP
	connDescriptor *conn = new connDescriptor(3, //com port ID
												38400, //baud rate
												0, //parity 0-4=None,Odd,Even,Mark,Space 
												0, //stop bit 0,1,2 = 1, 1.5, 2 
												8, //bits in byte 4-8 
												50 // timeout milli secs
											);
	ModUNI *mu = new ModUNI(conn);*/
	/******************************BYTEs_ARRAY****************************************/
	mu->SetString(1,"hello world");
	char test[255] = { 0 };
	mu->GetString(1, test, 11);
	printf("char array: %s\n", test);
	/*****************************TWO_BYTES_VALUE*************************************/
	short value2b = 0;
	mu->SetINT16(12, 923);
	mu->GetINT16(12, value2b);
	printf("TWO_BYTES_VALUE: %d\n", value2b);
	/****************************FOUR_BYTES_VALUE*************************************/
	int value4b = 0;
	mu->SetINT32(13, 753190);
	mu->GetINT32(13, value4b);
	printf("FOUR_BYTES_VALUE: %d\n", value4b);
	/****************************EIGHT_BYTES_VALUE*************************************/
	__int64 value8b = 0;
	mu->SetINT64(15, 890000006);
	mu->GetINT64(15, value8b);
	printf("EIGHT_BYTES_VALUE: %d\n", value4b);
	/****************************FLOAT4_BYTES_VALUE*************************************/
	float value_f4b = 0.0;
	mu->SetFloat(19, 8567.47);
	mu->GetFLOAT(19, value_f4b);
	printf("FLOAT4_BYTES_VALUE: %f\n", value_f4b);
	/****************************FLOAT8_BYTES_VALUE*************************************/
	double value_f8b = 0.0;
	mu->SetDOUBLE(23, 45639.57438);
	mu->GetDOUBLE(23, value_f8b);
	printf("FLOAT8_BYTES_VALUE: %lf\n", value_f8b);
	/***********************************************************************************/
	unsigned short ai1 = 0;
	mu->GetAIReg(1, ai1);
	printf("analog input: %d\n",ai1);
	/**********************************************************************************/
	mu->~ModUNI();
	_getch();
    return 0;
}


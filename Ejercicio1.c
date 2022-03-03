#include <sys/types.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#define PASS_LEN 6
#define E_BARRA 50

struct args{//argumentos compartidos
    pthread_mutex_t mutex;//mutex general
    long cnt;//contador para saber cada cuanto se tiene que aumentar la barra
    int yes;//para saber cuando le sumamos uno a la barra
    int blk;//para saber cuando tenemos que bloquear
    long limit;
    pthread_t id;
};

int comprobar(int * iter,pthread_mutex_t * mutex) {
  int temp;
  pthread_mutex_lock(mutex);
  temp =(*iter);
  pthread_mutex_unlock(mutex);
  return temp;
}

long ipow(long base, int exp)
{
    long res = 1;
    for (;;)
    {
        if (exp & 1)
            res *= base;
        exp >>= 1;
        if (!exp)
            break;
        base *= base;
    }

    return res;
}

long pass_to_long(char *str) {//convierte todo el string en un numero(revierte long to pass)
    long res = 0;

    for(int i=0; i < PASS_LEN; i++)
        res = res * 26 + str[i]-'a';

    return res;
};

void long_to_pass(long n, unsigned char *str) {  // str should have size PASS_SIZE+1
    for(int i=PASS_LEN-1; i >= 0; i--) {//convierte un numero en un string posible de contraseña
        str[i] = n % 26 + 'a';
        n /= 26;
    }
    str[PASS_LEN] = '\0';
}

int hex_value(char c) {//pasa de base 16 a base 10
    if (c>='0' && c <='9')
        return c - '0';
    else if (c>= 'A' && c <='F')
        return c-'A'+10;
    else if (c>= 'a' && c <='f')
        return c-'a'+10;
    else return 0;
}

void hex_to_num(char *str, unsigned char *hex) {//trabajamos en base 10, te convierte un string que le pases en base 16 a base 10, el valor del hash que nos
//devuelve el terminal es en base 16, aquí lo pasamos a base 10
    for(int i=0; i < MD5_DIGEST_LENGTH; i++)
        hex[i] = (hex_value(str[i*2]) << 4) + hex_value(str[i*2 + 1]);
}

char *break_pass(unsigned char *md5, struct args *args) {//md5 es la contraseña
    unsigned char res[MD5_DIGEST_LENGTH];
    unsigned char *pass = malloc((PASS_LEN + 1) * sizeof(char));
    long bound = ipow(26, PASS_LEN); // we have passwords of PASS_LEN
                                     // lowercase chars =>
                                    //     26 ^ PASS_LEN  different cases

    for(long i=0; i < bound; i++) {
        long_to_pass(i, pass);//cada i es una de las opciones de contraseña, por lo tanto convierte esa i en un char posible

        MD5(pass, PASS_LEN, res); //te hace el hash de la funcion pero ya con los valores en base 10
        pthread_mutex_lock(&args->mutex);
        args->cnt++;
        if(args->cnt==args->limit && args->yes==0){
            args->yes=1;
            args->cnt=0;

        }
        if(0 == memcmp(res, md5, MD5_DIGEST_LENGTH)){
            args->blk=0;
            pthread_mutex_unlock(&args->mutex);
            break;
        } // Found it!
        //te compara a ver si es o no la contraseña el pass(compara en hexadecimal pero en base 10)
        pthread_mutex_unlock(&args->mutex);

    }

    return (char *) pass; //te devuelve el pass que era
}


 
void *progressBar(void* ptr){
    struct args *args =  ptr;
        int i = 0;
        char bar[E_BARRA+1];
        memset(bar, 0, sizeof(bar));

        const char *lable = "|/-\\";
        while(comprobar(&args->blk,&args->mutex)){
            printf("[%-50s][%d%%][%c]\r", bar, (i*2), lable[i %4 ]);
            fflush(stdout);
            pthread_mutex_lock(&args->mutex);
            if(i<E_BARRA && args->yes){
                bar[i++] = '#';
                args->yes=0;
            }
            pthread_mutex_unlock(&args->mutex);
        }
        usleep(1000000);
        
        return NULL;
}

struct args  *lanzar_barra(){//vamos a tener memory leaks tener en cuenta
    struct args *args= malloc(sizeof(struct args));
    long iters= ipow(26,PASS_LEN);
    args->limit = iters/E_BARRA;
    args->cnt=0;
    args->blk=1;
    args->yes=0;
    pthread_mutex_init(&args->mutex,NULL);
    pthread_create(&args->id,NULL,progressBar,args);
    return args;

}

void destruir(struct args *args){
    pthread_join(args->id,NULL);
    pthread_mutex_destroy(&args->mutex);
    free(args);


}

int main(int argc, char *argv[]) {
    if(argc < 2) {
        printf("Use: %s string\n", argv[0]);
        exit(0);
    }
    struct args *args;

    args=lanzar_barra();

    unsigned char md5_num[MD5_DIGEST_LENGTH];
    hex_to_num(argv[1], md5_num);//convertimos la contraseña a hexadecimal porque el hash trabaja con estos

    char *pass = break_pass(md5_num,args);

    printf("%s: %s                                        \n", argv[1], pass);
    destruir(args);//destruye args
    free(pass);
    return 0;
}

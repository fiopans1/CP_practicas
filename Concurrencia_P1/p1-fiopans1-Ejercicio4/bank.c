#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include "options.h"

#define MAX_AMOUNT 20
struct bank {
    int num_accounts;        // number of accounts
    int *accounts;           // balance array
    pthread_mutex_t *mutex;  //array de mutex(uno por cuenta)
};

struct args {
    int          thread_num;  // application defined thread #
    int          delay;       // delay between operations
    int	         *iterations;  // number of operations
    pthread_mutex_t *mutex;
    int          net_total;   // total amount deposited by this thread
    struct bank *bank;        // pointer to the bank (shared with other threads)
};

struct thread_info {
    pthread_t    id;    // id returned by pthread_create()
    struct args *args;  // pointer to the arguments
};


struct total{//este struct se usa en el hilo que calcula los totales del banco
    struct bank *bank;
    int cnt;
    pthread_mutex_t mutex;
    pthread_t id;
};

//funciones auxiliares para los while
int descontar_una(int * iter,pthread_mutex_t * mutex) {
  int temp;
  pthread_mutex_lock(mutex);
  temp = *iter ? (*iter)-- : 0;
  pthread_mutex_unlock(mutex);
  return temp;
}
int aumentar_una(int * iter,pthread_mutex_t * mutex) {
  int temp;
  pthread_mutex_lock(mutex);
  temp =(*iter)++;
  pthread_mutex_unlock(mutex);
  return temp;
}
int comprobar(int * iter,pthread_mutex_t * mutex) {
  int temp;
  pthread_mutex_lock(mutex);
  temp =(*iter);
  pthread_mutex_unlock(mutex);
  return temp;
}
// Threads run on this function
void *deposit(void *ptr) //los threads solo ejecutan esta funcion
{
    struct args *args =  ptr;
    int amount, account, balance;

    while(descontar_una(args->iterations,args->mutex)) {//mientras el numero de iteraciones sea mayor que 0, se ejecuta
        amount  = rand() % MAX_AMOUNT;
        account = rand() % args->bank->num_accounts; //saca un aleatorio para saber en que cuenta hacemos el deposito

        printf("Thread %d depositing %d on account %d\n",
            args->thread_num, amount, account);
        //*********************SECCION CRITICA********************************
        pthread_mutex_lock(&args->bank->mutex[account]);//block
        
        balance = args->bank->accounts[account];
        if(args->delay) usleep(args->delay); // Force a context switch

        balance += amount;
        if(args->delay) usleep(args->delay);


        args->bank->accounts[account] = balance;
        
        pthread_mutex_unlock(&args->bank->mutex[account]);//unblock
        //********************************************************************
        if(args->delay) usleep(args->delay);

        args->net_total += amount;
    }
    return NULL;
}

void *transferencia(void *ptr){
    struct args *args =  ptr;
    int amount, account1, account2, balance, tmp;

    while(descontar_una(args->iterations,args->mutex)){
        account1 = rand() % args->bank->num_accounts;
        account2 = rand() % args->bank->num_accounts;
        if(account1 != account2){//sino da error
            while(1){
                pthread_mutex_lock(&args->bank->mutex[account1]);
                if(pthread_mutex_trylock(&args->bank->mutex[account2])){
                    pthread_mutex_unlock(&args->bank->mutex[account1]);
                    continue;
                }
                
                tmp = args->bank->accounts[account1];
                if(tmp != 0){ //sino da error
                    amount = rand() % tmp;
                    printf("EL hilo %d transfiere %d de la cuenta %d a la cuenta %d %d\n",
                    args->thread_num,amount,account1,account2, *args->iterations);
                    if(args->delay) usleep(args->delay);
                    balance=args->bank->accounts[account1];
                    if(args->delay) usleep(args->delay);
                    balance-=amount;
                    if(args->delay) usleep(args->delay);
                    args->bank->accounts[account1]=balance;
                    if(args->delay) usleep(args->delay);
                    balance = args->bank->accounts[account2];
                    if(args->delay) usleep(args->delay);
                    balance+=amount;
                    if(args->delay) usleep(args->delay);
                    args->bank->accounts[account2]= balance;
                }else{

                    aumentar_una(args->iterations,args->mutex); 
                }
                pthread_mutex_unlock(&args->bank->mutex[account1]);
                pthread_mutex_unlock(&args->bank->mutex[account2]);
                break;
            }
            if(args->delay) usleep(args->delay);

            args->net_total+=amount;
        }else{
            aumentar_una(args->iterations,args->mutex); 
        }

    }
    return NULL;
}





void *calcular_totales(void *ptr){//tenemos que bloquear el array de mutex todos para hacer el for
//
    struct total *tt= ptr;
    int total=0;
    while(comprobar(&tt->cnt,&tt->mutex)){
        for(int i=0; i<tt->bank->num_accounts;i++){
            pthread_mutex_lock(&tt->bank->mutex[i]);
        }

        for(int i=0;i<tt->bank->num_accounts;i++){
            total=total + (tt->bank->accounts[i]);
                
                
        }

        for(int i=0; i<tt->bank->num_accounts;i++){
            pthread_mutex_unlock(&tt->bank->mutex[i]);
        }
        printf("Total del banco : %d\n", total);
        usleep(300);
        total=0;

    }
    return NULL;
}








// start opt.num_threads threads running on deposit.
struct thread_info *start_threads(struct options opt, struct bank *bank, void *(function)(void *))
//para reusar este codigo para transferencias elegimos que funcion ejecuta
{
    int i, *iters;
    pthread_mutex_t *mutex;
    struct thread_info *threads;

    printf("creating %d threads\n", opt.num_threads);
    threads = malloc(sizeof(struct thread_info) * opt.num_threads);//crea un array de threads

    if (threads == NULL) {
        printf("Not enough memory\n");
        exit(1);
    }
    mutex = malloc(sizeof(pthread_mutex_t));
    iters = malloc(sizeof(int));
    pthread_mutex_init(mutex, NULL);
    *iters = opt.iterations;

    // Create num_thread threads running swap()
    for (i = 0; i < opt.num_threads; i++) {
        threads[i].args = malloc(sizeof(struct args));

        threads[i].args -> thread_num = i;
        threads[i].args -> net_total  = 0;
        threads[i].args -> bank       = bank;//variable compartida
        threads[i].args -> delay      = opt.delay;
        threads[i].args -> iterations = iters;
        threads[i].args -> mutex      = mutex;
        if (0 != pthread_create(&threads[i].id, NULL, function, threads[i].args)) {
            printf("Could not create thread #%d", i);
            exit(1);
        }
    }

    return threads;
}


// Print the final balances of accounts and threads
void print_balances(struct bank *bank, struct thread_info *thrs, int num_threads) {
    int total_deposits=0, bank_total=0;
    printf("\nNet deposits by thread\n");//dinero que despositaron los hilos

    for(int i=0; i < num_threads; i++) {//mira cuanto desposito cada hilo e imprime el total
        printf("%d: %d\n", i, thrs[i].args->net_total);
        total_deposits += thrs[i].args->net_total;
    }
    printf("Total: %d\n", total_deposits);

    printf("\nAccount balance\n");
    for(int i=0; i < bank->num_accounts; i++) {//mira cuanto tiene cada cuenta e imprime el total

        pthread_mutex_lock(&bank->mutex[i]);//block
        printf("%d: %d\n", i, bank->accounts[i]);
        bank_total += bank->accounts[i];
        pthread_mutex_unlock(&bank->mutex[i]);//unblock
        
    }
    printf("Total: %d\n", bank_total);
}


void print_transference(struct bank *bank, struct thread_info *thrs, int num_threads) {
    int total_transference=0, bank_total=0;
    printf("\nNet transfers by thread\n");//dinero que despositaron los hilos

    for(int i=0; i < num_threads; i++) {//mira cuanto desposito cada hilo e imprime el total
        printf("%d: %d\n", i, thrs[i].args->net_total);
        total_transference += thrs[i].args->net_total;
    }
    printf("Total: %d\n", total_transference);

    printf("\nAccount balance\n");
    for(int i=0; i < bank->num_accounts; i++) {//mira cuanto tiene cada cuenta e imprime el total

        pthread_mutex_lock(&bank->mutex[i]);//block
        printf("%d: %d\n", i, bank->accounts[i]);
        bank_total += bank->accounts[i];
        pthread_mutex_unlock(&bank->mutex[i]);//unblock
        
    }
    printf("Total: %d\n", bank_total);
}

void wait_depositos(struct options opt, struct bank *bank, struct thread_info *threads) {
    // Wait for the threads to finish
    for (int i = 0; i < opt.num_threads; i++)
        pthread_join(threads[i].id, NULL);

    print_balances(bank, threads, opt.num_threads);
    free(threads[0].args->iterations);
    pthread_mutex_destroy(threads[0].args->mutex);
    free(threads[0].args->mutex);
    for (int i = 0; i < opt.num_threads; i++)
        free(threads[i].args);
    free(threads);
}
// wait for all threads to finish, print totals, and free memory
void wait_transferencias(struct options opt, struct bank *bank, struct thread_info *threads, struct total *tt) {
    // Wait for the threads to finish
    for (int i = 0; i < opt.num_threads; i++){
        pthread_join(threads[i].id, NULL);
    }

    pthread_mutex_lock(&tt->mutex);//seccion critica para parar el while del calcular total banco
    tt->cnt = 0;
    pthread_mutex_unlock(&tt->mutex);

    pthread_join(tt->id,NULL);//esperamos al hilo de totales
    print_transference(bank, threads, opt.num_threads);

    free(threads[0].args->iterations);
    pthread_mutex_destroy(threads[0].args->mutex);
    free(threads[0].args->mutex);
    for (int i = 0; i < opt.num_threads; i++){
        free(threads[i].args);
    }
    pthread_mutex_unlock(&tt->mutex);
    free(tt);
    free(threads);
    for(int i=0;i<bank->num_accounts;i++){
        pthread_mutex_destroy(&bank->mutex[i]);
    }
    free(bank->accounts);
    free(bank->mutex);
}


// allocate memory, and set all accounts to 0
void init_accounts(struct bank *bank, int num_accounts) {//inicializa un array con num_accounts posiciones, y cada una representa una cuenta de banco
    bank->num_accounts = num_accounts;
    bank->accounts     = malloc(bank->num_accounts * sizeof(int));
    bank->mutex        = malloc(bank->num_accounts * sizeof(pthread_mutex_t));

    for(int i=0; i < bank->num_accounts; i++){
        bank->accounts[i] = 0;
        pthread_mutex_init(&bank->mutex[i],NULL);
    }
    
}
struct total *init_total(struct bank *bank){
    struct total *tt=malloc(sizeof(struct total));
    tt->bank = bank;
    tt->cnt = 1;
    pthread_mutex_init(&tt->mutex,NULL);
    pthread_create(&tt->id,NULL,calcular_totales, tt);

    return tt;
}
int main (int argc, char **argv)
{
    struct options      opt; //este va a contener las variables para inicializar
    struct bank         bank;//esta va a ser la variable compartida por todos los hilos
    struct thread_info *thrs;
    struct total *tt;
    
    srand(time(NULL));

    // Default values for the options
    opt.num_threads  = 5;
    opt.num_accounts = 10;
    opt.iterations   = 100;
    opt.delay        = 10;

    read_options(argc, argv, &opt);//iguala los valores a las opciones

    init_accounts(&bank, opt.num_accounts);//inicializa las cuentas

    thrs = start_threads(opt, &bank,deposit);//crea los hilos y hace que ejecute desposito
    wait_depositos(opt, &bank, thrs);
    
    thrs = NULL;
    thrs = start_threads(opt, &bank,transferencia);//crea los hilos y hace que ejecute transferencia
    tt = init_total(&bank);//crea el hilo del total del banco    
    wait_transferencias(opt, &bank, thrs, tt);
    return 0;
}

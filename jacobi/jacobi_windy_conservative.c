#include <stdio.h>
#include <math.h>

#ifdef _OPENMP
#include <omp.h>
#endif

// windy
#include "sescapi.h"

// Add timing support
#include <sys/time.h>
double time_stamp()
{
  struct timeval t;
  double time;
  gettimeofday(&t, NULL);
  time = t.tv_sec + 1.0e-6*t.tv_usec;
  return time;
}
double time1, time2;

void driver(void);
void initialize(void);
void jacobi(void);
void error_check(void);

/************************************************************
* program to solve a finite difference 
* discretization of Helmholtz equation :  
* (d2/dx2)u + (d2/dy2)u - alpha u = f 
* using Jacobi iterative method. 
*
* Modified: Sanjiv Shah,       Kuck and Associates, Inc. (KAI), 1998
* Author:   Joseph Robicheaux, Kuck and Associates, Inc. (KAI), 1998
* This c version program is translated by 
* Chunhua Liao, University of Houston, Jan, 2005 
* 
* Directives are used in this code to achieve paralleism. 
* All do loops are parallized with default 'static' scheduling.
* 
* Input :  n - grid dimension in x direction 
*          m - grid dimension in y direction
*          alpha - Helmholtz constant (always greater than 0.0)
*          tol   - error tolerance for iterative solver
*          relax - Successice over relaxation parameter
*          mits  - Maximum iterations for iterative solver
*
* On output 
*       : u(n,m) - Dependent variable (solutions)
*       : f(n,m) - Right hand side function 
*************************************************************/

 //#define MSIZE 500
 #define MSIZE 16
 int n,m,mits; 
 double tol,relax=1.0,alpha=0.0543; 
 double u[MSIZE][MSIZE],f[MSIZE][MSIZE],uold[MSIZE][MSIZE];
 double dx,dy;

int main (void) 
{
  float toler;
  /*      printf("Input n,m (< %d) - grid dimension in x,y direction:\n",MSIZE); 
          scanf ("%d",&n);
          scanf ("%d",&m);
          printf("Input tol - error tolerance for iterative solver\n"); 
          scanf("%f",&toler);
          tol=(double)toler;
          printf("Input mits - Maximum iterations for solver\n"); 
          scanf("%d",&mits);
          */
  n=MSIZE;
  m=MSIZE;
  tol=0.0000000001;
  mits=5000;

	// windy
	wb_word(&n);
	wb_word(&m);
	wb_dword(&tol);
	wb_word(&mits);

#ifdef _OPENMP
	omp_set_num_threads(4);
#pragma omp parallel
  {
#pragma omp master
	{
    printf("Running using %d threads...\n",omp_get_num_threads());
	}
  }
#endif
  driver ( ) ;
  return 0;
}

/*************************************************************
* Subroutine driver () 
* This is where the arrays are allocated and initialzed. 
*
* Working varaibles/arrays 
*     dx  - grid spacing in x direction 
*     dy  - grid spacing in y direction 
*************************************************************/

void driver( )
{
  initialize();

  time1 = time_stamp();
  /* Solve Helmholtz equation */
  jacobi ();
  time2 = time_stamp();

  printf("------------------------\n");     
  printf("Execution time = %f\n",time2-time1);
  /* error_check (n,m,alpha,dx,dy,u,f)*/
  error_check ( );
}


/*      subroutine initialize (n,m,alpha,dx,dy,u,f) 
******************************************************
* Initializes data 
* Assumes exact solution is u(x,y) = (1-x^2)*(1-y^2)
*
******************************************************/

void initialize( )
{
      
      int i,j, xx,yy;
      //double PI=3.1415926;

      dx = 2.0 / (n-1);
      dy = 2.0 / (m-1);
		// windy
		wb_dword(&dx);
		wb_dword(&dy);

/* Initialize initial condition and RHS */

// windy, pragma change
//#pragma omp parallel for private(xx,yy,j,i)
#pragma omp parallel 
{
	// windy
	inv_word(&n);
	inv_word(&m);
	inv_dword(&dx);
	inv_dword(&dy);

	#pragma omp for private(xx,yy,j,i)
       for (i=0;i<n;i++)
         for (j=0;j<m;j++)      
           {
            xx =(int)( -1.0 + dx * (i-1));        
            yy = (int)(-1.0 + dy * (j-1)) ;       
            u[i][j] = 0.0;                       
            f[i][j] = -1.0*alpha *(1.0-xx*xx)*(1.0-yy*yy)\
               - 2.0*(1.0-xx*xx)-2.0*(1.0-yy*yy);  
			// windy
			wb_dword(&u[i][j]);
			wb_dword(&f[i][j]);
          }
}

}

/*      subroutine jacobi (n,m,dx,dy,alpha,omega,u,f,tol,maxit)
******************************************************************
* Subroutine HelmholtzJ
* Solves poisson equation on rectangular grid assuming : 
* (1) Uniform discretization in each direction, and 
* (2) Dirichlect boundary conditions 
* 
* Jacobi method is used in this routine 
*
* Input : n,m   Number of grid points in the X/Y directions 
*         dx,dy Grid spacing in the X/Y directions 
*         alpha Helmholtz eqn. coefficient 
*         omega Relaxation factor 
*         f(n,m) Right hand side function 
*         u(n,m) Dependent variable/Solution
*         tol    Tolerance for iterative solver 
*         maxit  Maximum number of iterations 
*
* Output : u(n,m) - Solution 
*****************************************************************/

void jacobi( )
{
  double omega;
  int i,j,k;
  // windy
  //double  error,resid,ax,ay,b;
  double  resid,ax,ay,b;
  static double error;
  //      double  error_local;

  //      float ta,tb,tc,td,te,ta1,ta2,tb1,tb2,tc1,tc2,td1,td2;
  //      float te1,te2;
  //      float second;

  omega=relax;
  /*
   * Initialize coefficients */

  ax = 1.0/(dx*dx); /* X-direction coef */
  ay = 1.0/(dy*dy); /* Y-direction coef */
  b  = -2.0/(dx*dx)-2.0/(dy*dy) - alpha; /* Central coeff */ 

  error = 10.0 * tol;
  k = 1;
	// windy
	wb_dword(&error);

  while ((k<=mits)&&(error>tol)) 
  {
    error = 0.0;    
	// windy
	wb_dword(&error);

    /* Copy new solution into old */
#pragma omp parallel
    {
		// windy
		inv_word(&n);
		inv_word(&m);
#pragma omp for private(j,i)
      for(i=0;i<n;i++)   
        for(j=0;j<m;j++) 
		{
			// windy
			inv_dword(&u[i][j]);
          uold[i][j] = u[i][j]; 
			// windy
			wb_dword(&uold[i][j]);
		}

		// windy
		inv_word(&n);
		inv_word(&m);
		inv_dword(&error);
//#pragma omp for private(resid,j,i) reduction(+:error) nowait
//#pragma omp for private(resid,j,i) reduction(+:error)
#pragma omp for private(resid,j,i) 
      for (i=1;i<(n-1);i++)  
        for (j=1;j<(m-1);j++)   
        { 
			// windy
			inv_dword(&uold[i-1][j]);
			inv_dword(&uold[i+1][j]);
			inv_dword(&uold[i][j-1]);
			inv_dword(&uold[i][j+1]);
			inv_dword(&uold[i][j]);
			inv_dword(&f[i][j]);
			

          resid = (ax*(uold[i-1][j] + uold[i+1][j])\
              + ay*(uold[i][j-1] + uold[i][j+1])+ b * uold[i][j] - f[i][j])/b;  

          u[i][j] = uold[i][j] - omega * resid;  
			// windy
			wb_dword(&u[i][j]);
#pragma omp critical 
{
			inv_dword(&error);
          error = error + resid*resid ;   
			// windy
			wb_dword(&error);
}
        }

    }
    /*  omp end parallel */

    /* Error check */

    k = k + 1;
    if (k%500==0) 
      printf("** Finished %d iteration.\n",k);
    printf("Finished %d iteration.\n",k);
	// windy
	inv_dword(&error);
    error = sqrt(error)/(n*m);
	wb_dword(&error);

  }          /*  End iteration loop */

  printf("Total Number of Iterations:%d\n",k); 
  printf("Residual:%E\n", error); 

}
/*      subroutine error_check (n,m,alpha,dx,dy,u,f) 
      implicit none 
************************************************************
* Checks error between numerical and exact solution 
*
************************************************************/ 
void error_check ( )
{ 
  int i,j;
// windy
//  double xx,yy,temp,error; 
  double xx,yy,temp; 
  static double error;

  dx = 2.0 / (n-1);
  dy = 2.0 / (m-1);
  error = 0.0 ;

	// windy
	wb_dword(&dx);
	wb_dword(&dy);
	wb_dword(&error);

//#pragma omp parallel for private(xx,yy,temp,j,i) reduction(+:error)
#pragma omp parallel 
{
	// windy
	inv_dword(&dx);
	inv_dword(&dy);
//#pragma omp for private(xx,yy,temp,j,i) reduction(+:error)
#pragma omp for private(xx,yy,temp,j,i)
  for (i=0;i<n;i++)
    for (j=0;j<m;j++)
    { 
      xx = -1.0 + dx * (i-1);
      yy = -1.0 + dy * (j-1);
	// windy
	inv_dword(&u[i][j]);
      temp  = u[i][j] - (1.0-xx*xx)*(1.0-yy*yy);
	#pragma omp critical
	{
	// windy
	inv_dword(&error);
      error = error + temp*temp; 
	// windy
	wb_dword(&error);
	}
    }
}

	inv_dword(&error);
  error = sqrt(error)/(n*m);
  printf("Solution Error :%E \n",error);
}


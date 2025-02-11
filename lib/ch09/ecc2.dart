import 'huge2.dart';
import 'ecc_tables.dart';

class Point {
  Huge x;
  Huge y;
  Point(this.x, this.y);
}

class EllipticCurve {
  Huge p;
  Huge a;
  Huge b;
  Point G;
  Huge n; // n is prime and is the "order" of G
  Huge h; // h = #E(F_p)/n (# is the number of Points on the curve)

  EllipticCurve(this.p, this.a, this.b, this.G, this.n, this.h);
}

class EccKey {
  Huge d; // random integer < n; this is the private key
  Point Q; // Q = d * G; this is the public key

  EccKey(this.d, this.Q);
}


void multiply_point( Point p1, Huge k, Huge a, Huge p )
{
  int i;
  int mask;
  Point dp;
  int paf = 1;

  // set_huge( dp.x, 0 );
  // set_huge( dp.y, 0 );
dp=Point(Huge.from(0),Huge.from(0));


  // copy_huge( dp.x, p1.x );
  // copy_huge( dp.y, p1.y );
p1=Point(Huge.from(0),Huge.from(0));

  for ( i = k.size; i!=0; i-- )
  {
    for ( mask = 0x01; mask!=0; mask <<= 1 )
    {
      if ( k.rep[ i - 1 ] & mask )
      {
       if ( paf )
       {
         paf = 0;
         copy_huge( p1.x, dp.x );
         copy_huge( p1.y, dp.y );
       }
       else
       {
        //  add_points( p1, dp, p );
        
       }
     }
     // double dp
     double_point( dp, a, p );
    }
  } 



  free_huge( dp.x );
  free_huge( dp.y );
}

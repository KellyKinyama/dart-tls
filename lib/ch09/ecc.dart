import 'huge.dart';
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

int sizeof(List<int> input){
return input.length;
}



int get_named_curve( String curve_name, EllipticCurve target )
{
  if (  ("prime192v1"== curve_name ) ||
      ( "secp192r1"== curve_name ) )
  {
    load_huge( target.p, prime192v1_P, sizeof( prime192v1_P ) );
    load_huge( target.a, prime192v1_A, sizeof( prime192v1_A ) );
    load_huge( target.b, prime192v1_B, sizeof( prime192v1_B ) );
    load_huge( target.G.x, prime192v1_Gx, 
      sizeof( prime192v1_Gx ) );
    load_huge( target.G.y, prime192v1_Gy,
      sizeof( prime192v1_Gy ) );
    load_huge( target.n, prime192v1_N, sizeof( prime192v1_N ) );
    
    return 0;
  }
  else if ( ( "prime256v1"== curve_name ) ||
            ( "secp256r1"== curve_name ) )
  {
    load_huge( target.p, prime256v1_P, sizeof( prime256v1_P ) );
    load_huge( target.a, prime256v1_A, sizeof( prime256v1_A ) );
    load_huge( target.b, prime256v1_B, sizeof( prime256v1_B ) );
    load_huge( target.G.x, prime256v1_Gx,
      sizeof( prime256v1_Gx ) );
    load_huge( target.G.y, prime256v1_Gy,
      sizeof( prime256v1_Gy ) );
    load_huge( target.n, prime256v1_N, sizeof( prime256v1_N ) );

    return 0;
  }

  // Unsupported named curve

  return 1;
}

void add_points( Point p1, Point p2, Huge p )
{
  Point p3;
  Huge denominator;
  Huge numerator;
  Huge invdenom;
  Huge lambda;

  set_huge( denominator, 0 ); 
  copy_huge( denominator, p2.x );    // denominator = x2
  subtract( denominator, p1.x );     // denominator = x2 - x1
  set_huge( numerator, 0 );
  copy_huge( numerator, p2.y );      // numerator = y2
  subtract( numerator, p1.y );       // numerator = y2 - y1
  set_huge( invdenom, 0 );
  copy_huge( invdenom, denominator );
  inv( invdenom, p );
  set_huge( lambda, 0 );
  copy_huge( lambda, numerator );
  multiply( lambda, invdenom );       // lambda = numerator / denominator
  set_huge( p3.x, 0 );
  copy_huge( p3.x, lambda );    // x3 = lambda
  multiply( p3.x, lambda );     // x3 = lambda * lambda
  subtract( p3.x, p1.x );      // x3 = ( lambda * lambda ) - x1
  subtract( p3.x, p2.x );      // x3 = ( lambda * lambda ) - x1 - x2

  divide( p3.x, p, null );       // x3 = ( ( lamdba * lambda ) - x1 - x2 ) % p

  // positive remainder always
  if ( p3.x.sign ) 
  {
    p3.x.sign = 0;
    subtract( p3.x, p );
    p3.x.sign = 0;
  }

  set_huge( p3.y, 0 );
  copy_huge( p3.y, p1.x );    // y3 = x1
  subtract( p3.y, p3.x );      // y3 = x1 - x3
  multiply( p3.y, lambda );    // y3 = ( x1 - x3 ) * lambda
  subtract( p3.y, p1.y );     // y3 = ( ( x1 - x3 ) * lambda ) - y

  divide( p3.y, p, null );
  // positive remainder always
  if ( p3.y.sign )
  {
    p3.y.sign = 0;
    subtract( p3.y, p );
    p3.y.sign = 0;
  }

  // p1.x = p3.x
  // p1.y = p3.y
  copy_huge( p1.x, p3.x );
  copy_huge( p1.y, p3.y );

  free_huge( p3.x );
  free_huge( p3.y );
  free_huge( denominator );
  free_huge( numerator );
  free_huge( invdenom );
  free_huge( lambda );
}

static void double_point( Point p1, Huge a, Huge p )
{
  Huge lambda;
  Huge l1;
  Huge x1;
  Huge y1;

  set_huge( lambda, 0 );
  set_huge( x1, 0 );
  set_huge( y1, 0 );
  set_huge( lambda, 2 );     // lambda = 2;
  multiply( lambda, p1.y );  // lambda = 2 * y1
  inv( lambda, p );       // lambda = ( 2 * y1 ) ^ -1 (% p)

  set_huge( l1, 3 );       // l1 = 3
  multiply( l1, p1.x );    // l1 = 3 * x
  multiply( l1, p1.x );    // l1 = 3 * x ^ 2
  add( &l1, a );         // l1 = ( 3 * x ^ 2 ) + a
  multiply( lambda, l1 );    // lambda = [ ( 3 * x ^ 2 ) + a ] / [ 2 * y1 ] ) % p
  copy_huge( y1, p1.y );
  // Note - make two copies of x2; this one is for y1 below
  copy_huge( p1.y, p1.x );
  set_huge( x1, 2 );
  multiply( x1, p1.x );    // x1 = 2 * x1

  copy_huge( p1.x, lambda );  // x1 = lambda
  multiply( p1.x, lambda );  // x1 = ( lambda ^ 2 );
  subtract( p1.x, x1 );    // x1 = ( lambda ^ 2 ) - ( 2 * x1 )
  divide( p1.x, p, null );   // [ x1 = ( lambda ^ 2 ) - ( 2 * x1 ) ] % p
  
  if ( p1.x.sign )
  {
    subtract( p1.x, p );
    p1.x.sign = 0;
    subtract( p1.x, p );
  }
  subtract( p1.y, p1.x );  // y3 = x3 � x1
  multiply( p1.y, lambda ); // y3 = lambda * ( x3 - x1 );
  subtract( p1.y, y1 );   // y3 = ( lambda * ( x3 - x1 ) ) - y1
  divide( p1.y, p, null );  // y3 = [ ( lambda * ( x3 - x1 ) ) - y1 ] % p
  if ( p1.y.sign )
  {
    p1.y.sign = 0;
    subtract( p1.y, p );
    p1.y.sign = 0;
  }

  free_huge( lambda );
  free_huge( x1 );
  free_huge( y1 );
  free_huge( l1 );
}

void multiply_point( Point p1, Huge k, Huge a, Huge p )
{
  int i;
  int mask;
  Point dp=Point(set_huge(  0 ), set_huge(  0 ));
  int paf = 1;

  // set_huge( dp.x, 0 );
  // set_huge( dp.y, 0 );
  copy_huge( dp.x, p1.x );
  copy_huge( dp.y, p1.y );
  for ( i = k.size; i!=0; i-- )
  {
    for ( mask = 0x01; mask!=0; mask <<= 1 )
    {
      if ( (k.rep[ i - 1 ] & mask)!=0 )
      {
       if ( paf !=0)
       {
         paf = 0;
         copy_huge( p1.x, dp.x );
         copy_huge( p1.y, dp.y );
       }
       else
       {
         add_points( p1, dp, p );
       }
     }
     // double dp
     double_point( dp, a, p );
    }
  } 

  // free_huge( dp.x );
  // free_huge( dp.y );
}

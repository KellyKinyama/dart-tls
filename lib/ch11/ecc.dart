import 'huge2.dart';

class Point {
  Huge x;
  Huge y;

  Point(this.x, this.y);

  void copyFrom(Point other) {
    x.copyFrom(other.x);
    y.copyFrom(other.y);
  }
}

void addPoints(Point p1, Point p2, Huge p) {
  Point p3 = Point(Huge(0), Huge(0));
  Huge denominator = Huge(0);
  Huge numerator = Huge(0);
  Huge invdenom = Huge(0);
  Huge lambda = Huge(0);

  denominator.copyFrom(p2.x);
  denominator.subtractMagnitude(p1.x);
  
  numerator.copyFrom(p2.y);
  numerator.subtractMagnitude(p1.y);
  
  invdenom.copyFrom(denominator);
  // inv function needs to be implemented for Huge
  // invdenom.inv(p);
  
  lambda.copyFrom(numerator);
  lambda.multiply(invdenom);
  
  p3.x.copyFrom(lambda);
  p3.x.multiply(lambda);
  p3.x.subtractMagnitude(p1.x);
  p3.x.subtractMagnitude(p2.x);

  // Ensure positive remainder: p3.x = p3.x % p
  // Modular arithmetic needs to be added in Huge
  
  p3.y.copyFrom(p1.x);
  p3.y.subtractMagnitude(p3.x);
  p3.y.multiply(lambda);
  p3.y.subtractMagnitude(p1.y);
  
  // Ensure positive remainder: p3.y = p3.y % p
  
  p1.copyFrom(p3);
}

void doublePoint(Point p1, Huge a, Huge p) {
  Huge lambda = Huge(0);
  Huge l1 = Huge(3);
  Huge x1 = Huge(2);
  Huge y1 = Huge(0);

  l1.multiply(p1.x);
  l1.multiply(p1.x);
  l1.addMagnitude(a);
  
  lambda.copyFrom(p1.y);
  lambda.multiply(Huge(2));
  // lambda.inv(p);
  
  lambda.multiply(l1);
  
  y1.copyFrom(p1.y);
  p1.y.copyFrom(p1.x);
  p1.x.copyFrom(lambda);
  p1.x.multiply(lambda);
  p1.x.subtractMagnitude(x1);
  
  p1.y.subtractMagnitude(p1.x);
  p1.y.multiply(lambda);
  p1.y.subtractMagnitude(y1);
}

void multiplyPoint(Point p1, Huge k, Huge a, Huge p) {
  Point dp = Point(Huge(0), Huge(0));
  dp.copyFrom(p1);
  bool paf = true;

  for (int i = k.size; i > 0; i--) {
    for (int mask = 0x01; mask <= 0x80; mask <<= 1) {
      if ((k.rep[i - 1] & mask) != 0) {
        if (paf) {
          paf = false;
          p1.copyFrom(dp);
        } else {
          addPoints(p1, dp, p);
        }
      }
      doublePoint(dp, a, p);
    }
  }
}

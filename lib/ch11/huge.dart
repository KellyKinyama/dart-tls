import 'dart:typed_data';
import 'dart:math';

class Huge {
  late Uint8List rep;
  int size = 0;
  bool sign = false;

  Huge(int val) {
    setHuge(val);
  }

  void expand() {
    rep = Uint8List.fromList([1] + rep);
    size++;
  }

  void loadHuge(Uint8List bytes) {
    while (bytes.isNotEmpty && bytes[0] == 0) {
      bytes = bytes.sublist(1);
    }
    sign = false;
    size = bytes.length;
    rep = Uint8List.fromList(bytes);
  }

  void unloadHuge(Uint8List bytes) {
    bytes.setRange(bytes.length - size, bytes.length, rep);
  }

  void addMagnitude(Huge h2) {
    int maxSize = max(size, h2.size);
    Uint8List newRep = Uint8List(maxSize);
    int carry = 0;

    for (int i = 0; i < maxSize; i++) {
      int sum = (i < size ? rep[size - 1 - i] : 0) +
          (i < h2.size ? h2.rep[h2.size - 1 - i] : 0) +
          carry;
      carry = sum > 255 ? 1 : 0;
      newRep[maxSize - 1 - i] = sum & 0xFF;
    }

    rep = newRep;
    size = maxSize;
    if (carry > 0) {
      expand();
    }
  }

  void contract() {
    int i = 0;
    while (i < size && rep[i] == 0) {
      i++;
    }
    if (i > 0 && i < size) {
      rep = rep.sublist(i);
      size -= i;
    }
  }

  void subtractMagnitude(Huge h2) {
    int borrow = 0;
    for (int i = 0; i < size; i++) {
      int diff = (rep[size - 1 - i]) -
          (i < h2.size ? h2.rep[h2.size - 1 - i] : 0) -
          borrow;
      borrow = (diff < 0) ? 1 : 0;
      rep[size - 1 - i] = (diff & 0xFF);
    }
    contract();
  }

  void setHuge(int val) {
    sign = false;
    size = 4;
    int mask = 0xFF000000;
    while (mask > 0xFF && (val & mask) == 0) {
      size--;
      mask >>= 8;
    }
    rep = Uint8List(size);
    for (int i = 0; i < size; i++) {
      rep[size - 1 - i] = (val >> (i * 8)) & 0xFF;
    }
  }

  void leftShift() {
    int carry = 0;
    for (int i = size - 1; i >= 0; i--) {
      int newCarry = (rep[i] & 0x80) >> 7;
      rep[i] = ((rep[i] << 1) & 0xFF) | carry;
      carry = newCarry;
    }
    if (carry > 0) {
      expand();
    }
  }

  void multiply(Huge h2) {
    Huge temp = Huge(0);
    temp.copyFrom(this);
    setHuge(0);

    for (int i = 0; i < h2.size; i++) {
      for (int mask = 0x01; mask <= 0x80; mask <<= 1) {
        if ((h2.rep[h2.size - 1 - i] & mask) != 0) {
          addMagnitude(temp);
        }
        temp.leftShift();
      }
    }
  }

  void copyFrom(Huge other) {
    rep = Uint8List.fromList(other.rep);
    size = other.size;
    sign = other.sign;
  }
}

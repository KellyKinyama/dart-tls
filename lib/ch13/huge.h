#ifndef HUGE_H
#define HUGE_H

#include <memory>
#include <vector>

class Huge {
public:
    int sign;
    unsigned int size;
    std::unique_ptr<unsigned char[]> rep;

    Huge();
    Huge(unsigned int val);
    Huge(const Huge& other);
    Huge& operator=(const Huge& other);
    Huge(Huge&& other) noexcept;
    Huge& operator=(Huge&& other) noexcept;
    ~Huge();

    int compare(const Huge& other) const;
    void add(const Huge& other);
    void subtract(const Huge& other);
    void multiply(const Huge& other);
    void divide(const Huge& divisor, Huge& quotient);
    void load(const std::vector<unsigned char>& bytes);
    void unload(std::vector<unsigned char>& bytes) const;
    void modPow(const Huge& exp, const Huge& n, Huge& result);
    void inv(Huge& result) const;
    void contract();
};

#endif
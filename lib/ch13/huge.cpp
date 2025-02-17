#include <stdio.h>
#include <memory>
#include <string.h>
#include "huge.h"

/**
 * Extend the space for h by 1 char and set the LSB of that int
 * to 1.
 */
void expand(huge *h)
{
    auto tmp = std::move(h->rep);
    h->size++;
    h->rep = std::make_unique<unsigned char[]>(h->size);
    memcpy(h->rep.get() + 1, tmp.get(), (h->size - 1) * sizeof(unsigned char));
    h->rep[0] = 0x01;
}

/**
 * Given a byte array, load it into a "huge", aligning integers
 * appropriately
 */
void load_huge(huge *h, const unsigned char *bytes, int length)
{
    while (!( *bytes )) 
    { 
        bytes++; 
        length--; 
    }

    h->sign = 0;
    h->size = length;
    h->rep = std::make_unique<unsigned char[]>(length);
    memcpy(h->rep.get(), bytes, length);
}

void unload_huge(const huge *h, unsigned char *bytes, int length)
{
    memcpy(bytes + (length - h->size), h->rep.get(), length);
}

/**
 * Add two huges - overwrite h1 with the result.
 */
void add_magnitude(huge *h1, huge *h2)
{
    unsigned int i, j;
    unsigned int sum;
    unsigned int carry = 0;

    if (h2->size > h1->size) 
    {
        auto tmp = std::move(h1->rep);
        h1->rep = std::make_unique<unsigned char[]>(h2->size);
        memcpy(h1->rep.get() + (h2->size - h1->size), tmp.get(), h1->size);
        h1->size = h2->size;
    }

    i = h1->size;
    j = h2->size;

    do 
    {
        i--;
        if (j)
        { 
            j--;
            sum = h1->rep[i] + h2->rep[j] + carry;
        }
        else
        { 
            sum = h1->rep[i] + carry;
        }
        
        carry = sum > 0xFF;
        h1->rep[i] = sum;
    } while (i);

    if (carry)
    {
        expand(h1);
    }
}

/**
 * Go through h and see how many of the left-most bytes are unused.
 * Remove them and resize h appropriately.
 */
void contract(huge *h)
{
    int i = 0;

    while (!(h->rep[i]) && (i < h->size)) 
    { 
        i++; 
    }

    if (i && i < h->size)
    {
        auto tmp = &h->rep[i];
        h->rep = std::make_unique<unsigned char[]>(h->size - i);
        memcpy(h->rep.get(), tmp, h->size - i);
        h->size -= i;
    }
}

// You would apply the same process for the other functions, 
// replacing malloc/calloc/free with std::make_unique and moving 
// smart pointers instead of using raw pointers.

void copy_huge(huge *tgt, huge *src)
{
    tgt->sign = src->sign;
    tgt->size = src->size;
    tgt->rep = std::make_unique<unsigned char[]>(src->size);
    memcpy(tgt->rep.get(), src->rep.get(), (src->size * sizeof(unsigned char)));
}

void set_huge(huge *h, unsigned int val)
{
    unsigned int mask, i, shift;
    h->sign = 0;
    h->size = 4;

    for (mask = 0xFF000000; mask > 0x000000FF; mask >>= 8)
    {
        if (val & mask)
        {
            break;
        }
        h->size--;
    }

    h->rep = std::make_unique<unsigned char[]>(h->size);

    mask = 0x000000FF;
    shift = 0;
    for (i = h->size; i; i--)
    {
        h->rep[i - 1] = (val & mask) >> shift;
        mask <<= 8;
        shift += 8;
    }
}

// Further code changes would follow this pattern: where `malloc` or `calloc` is used,
// replace it with `std::make_unique` to create dynamic memory that will be managed by 
// the smart pointer. Additionally, raw pointer assignments and `free` calls are 
// replaced with smart pointer assignments and are handled automatically.


#include "City.h"
#include "CityCrc.h"

void CityHash32_test ( const void * key, int len, uint32_t seed, void * out )
{
  *(uint32*)out = CityHash32WithSeed((const char *)key,len,seed);
}

void CityHash64_test ( const void * key, int len, uint32_t seed, void * out )
{
  *(uint64*)out = CityHash64WithSeed((const char *)key,len,seed);
}

#if defined(__SSE4_2__) && (defined(__x86_64__) || defined(__e2k__))
void CityHash128_test ( const void * key, int len, uint32_t seed, void * out )
{
  uint128 s(0,0);

  s.first = seed;

  *(uint128*)out = CityHash128WithSeed((const char*)key,len,s);
}

void CityHashCrc128_test ( const void * key, int len, uint32_t seed, void * out )
{
  uint128 s(0,0);

  s.first = seed;

  *(uint128*)out = CityHashCrc128WithSeed((const char*)key,len,s);
}
#endif

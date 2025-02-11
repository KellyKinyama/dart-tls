
/** 
 * Check to see if the input starts with "0x"; if it does, return the decoded
 * bytes of the following data (presumed to be hex coded). If not, just return
 * the contents. This routine allocates memory, so has to be free'd.
 */
int hex_decode( List<int> input, List<List<int>> decoded )
{  
  int i;
  int len;

  // if(input.su)
    
  if ( strncmp( "0x", input, 2 ) )
  {
    len =  input.length + 1;
    decoded = List.filled(len, List.filled(len, 0));
    strcpy( decoded, input );
    len--;
  }
  else
  {
    len = ( input.length  >> 1 ) - 1;
    decoded = List.filled(len, List.filled(len, 0));
    for ( i = 2; i < input.length ; i += 2 )
    {
      (*decoded)[ ( ( i / 2 ) - 1 ) ] =
        ( ( ( input[ i ] <= '9' ) ? input[ i ] - '0' : 
        ( ( tolower( input[ i ] ) ) - 'a' + 10 ) ) << 4 ) |
        ( ( input[ i + 1 ] <= '9' ) ? input[ i + 1 ] - '0' : 
        ( ( tolower( input[ i + 1 ] ) ) - 'a' + 10 ) );
    }
  } 
 
  return len;
}

void show_hex( List<int> array, int length )
{
  while ( length-- !=0)
  {
    print( "${array++}.02x" );
  }
  print( "\n" );
}

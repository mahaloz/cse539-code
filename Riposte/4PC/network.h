#ifndef NETWORK_H__
#define NETWORK_H__
 
#include <memory>
#include <boost/asio.hpp>
 
using boost::asio::ip::tcp;
typedef std::shared_ptr<tcp::socket> socket_ptr;

  #define PORT_P1_P0 2000
  #define PORT_P0_P1 2001
  #define PORT_P0_P2 2002  
  #define PORT_P1_P2 2003 
  #define PORT_P0_P3 2004
  #define PORT_P1_P3 2005
  #define PORT_P3_P2 2006
 
  #define PORT_P1_P0_a 2007
  #define PORT_P0_P1_a 2008
  #define PORT_P0_P2_a 2009  
  #define PORT_P1_P2_a 2010 
  #define PORT_P0_P3_a 2011
  #define PORT_P1_P3_a 2012
  #define PORT_P3_P2_a 2013

  #define PORT_P1_P0_b 2014
  #define PORT_P0_P1_b 2015
  #define PORT_P0_P2_b 2016  
  #define PORT_P1_P2_b 2017 
  #define PORT_P0_P3_b 2018
  #define PORT_P1_P3_b 2019
  #define PORT_P3_P2_b 2020

  #define PORT_P1_P0_c 2021
  #define PORT_P0_P1_c 2022
  #define PORT_P0_P2_c 2023  
  #define PORT_P1_P2_c 2024 
  #define PORT_P0_P3_c 2025
  #define PORT_P1_P3_c 2026
  #define PORT_P3_P2_c 2027

  #define PORT_P1_P0_d 2028
  #define PORT_P0_P1_d 2029
  #define PORT_P0_P2_d 2030  
  #define PORT_P1_P2_d 2031 
  #define PORT_P0_P3_d 2032
  #define PORT_P1_P3_d 2033
  #define PORT_P3_P2_d 2034

/////////////////////////////////////////

 
#ifdef P_ZERO
  #define PORT_P2  PORT_P0_P2
  #define PORT_IN  PORT_P1_P0  
  #define PORT_OUT PORT_P0_P1 
  #define SELF     "P0"
  #define PARTNER  "P1"

  #define PORT_P2_DB  PORT_P0_P2_DB
  #define PORT_IN_DB  PORT_P1_P0_DB  
  #define PORT_OUT_DB PORT_P0_P1_DB 
  #define SELF_DB     "P0_DB"
  #define PARTNER_DB  "P1_DB"

  #define PORT_P2_DB_a  PORT_P0_P2_DB_a
  #define PORT_IN_DB_a  PORT_P1_P0_DB_a  
  #define PORT_OUT_DB_a PORT_P0_P1_DB_a 



#elif defined(P_ONE)
  #define PORT_P2  PORT_P1_P2
  #define PORT_IN  PORT_P0_P1 
  #define PORT_OUT PORT_P1_P0
  #define SELF     "P1"
  #define PARTNER  "P0"

  #define PORT_P2_DB  PORT_P1_P2_DB
  #define PORT_IN_DB  PORT_P0_P1_DB
  #define PORT_OUT_DB PORT_P1_P0_DB

  #define PORT_P2_DB_a  PORT_P1_P2_DB_a
  #define PORT_IN_DB_a  PORT_P0_P1_DB_a
  #define PORT_OUT_DB_a PORT_P1_P0_DB_a

  #define SELF_DB     "P1_DB"
  #define PARTNER_DB  "P0_DB"

#endif

template <typename T>
inline void swap(tcp::socket & s, T & x, size_t size = sizeof(T))
{
  
  boost::asio::async_write(s, boost::asio::buffer(&x, sizeof(T)),
    [](boost::system::error_code /*ec*/, std::size_t /*length*/) {});
  
  boost::asio::read(s, boost::asio::buffer(&x, sizeof(T)));


}

template <typename T>
inline void merge(tcp::socket & s, T & x)
{
  boost::asio::async_write(s, boost::asio::buffer(&x, sizeof(T)),
    [](boost::system::error_code /*ec*/, std::size_t /*length*/) {});
  T x2;
  boost::asio::read(s, boost::asio::buffer(&x2, sizeof(T)));
  x += x2;
}

#endif

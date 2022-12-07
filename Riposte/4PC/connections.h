
   #if (PARTY==0)
    std::cout << "P_ZERO: " << PORT_P0_P1 << std::endl;

    boost::asio::io_context io_context;
    
    tcp::resolver resolver(io_context);
 
    tcp::socket s2(io_context);
    boost::asio::connect(s2, resolver.resolve({host2,
    std::to_string(PORT_P0_P2)}));
    std::cerr << "P1: [Established connection to P2]" << std::endl;
     usleep(20000);
 
    tcp::socket s2_a(io_context);
    boost::asio::connect(s2_a, resolver.resolve({host2,
    std::to_string(PORT_P0_P2_a)}));
    std::cerr << "P1: [Established connection to P2]" << std::endl;
     usleep(20000);
 
    tcp::socket s3(io_context);
    boost::asio::connect(s3, resolver.resolve({host3,
    std::to_string(PORT_P0_P3)}));
    std::cout << "P0: [Established connection P3]" << std::endl;
     usleep(20000);
 

    tcp::socket s1(io_context);
    boost::asio::connect(s1, resolver.resolve({host1,
    std::to_string(PORT_P1_P0)}));
    std::cout << "P0: [Established connection P1]" << std::endl;
    usleep(20000);
 
  #endif



  #if (PARTY==1)
    
    std::cout << "P_ONE: " << PORT_P1_P0 << std::endl;
    boost::asio::io_context io_context;
    
    usleep(20000);
    tcp::resolver resolver(io_context);
    
    tcp::socket s2(io_context);
    boost::asio::connect(s2, resolver.resolve({host2,
    std::to_string(PORT_P1_P2)}));
    std::cerr << "P1: [Established connection to P2]" << std::endl;
     usleep(20000);
 
    tcp::socket s2_a(io_context);
    boost::asio::connect(s2_a, resolver.resolve({host2,
    std::to_string(PORT_P1_P2_a)}));
    std::cerr << "P1: [Established connection to P2]" << std::endl;
    
    usleep(20000); 
    tcp::socket s3(io_context);
    boost::asio::connect(s3, resolver.resolve({host3,
    std::to_string(PORT_P1_P3)}));
    std::cout << "P0: [Established connection P3]" << std::endl;
 
    usleep(20000);
    tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), PORT_P1_P0));
    std::cout << " --- > " << std::endl;
    tcp::socket s1(acceptor.accept());
    std::cerr << "Listenting on port: " << PORT_P1_P0 << std::endl;

   #endif

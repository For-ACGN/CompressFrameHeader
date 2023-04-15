package cfh

// Writer and Reader are used to compress frame
// header data like Ethernet, IPv4, IPv4, TCP and UDP.
// Usually, these data only change a small portion
// throughout the entire context.
//
// When call Write method, the compressor will compress
// data and write output to the under writer at once.
//
// 1. add new dictionary
// The new dictionary will be the top.
//
// +---------+-----------------+-----------------+
// | command | dictionary size | dictionary data |
// +---------+-----------------+-----------------+
// |  byte   |      uint8      |    var bytes    |
// +---------+-----------------+-----------------+
//
// 2. write changed data with existed dictionary
//
// +---------+------------------+-------------+-----------+
// | command | dictionary index | data number |   data    |
// +---------+------------------+-------------+-----------+
// |  byte   |      uint8       |    uint8    | var bytes |
// +---------+------------------+-------------+-----------+
//
// changed data structure
// index means changed data offset, data is the new byte
//
// +-------+------+
// | index | data |
// +-------+------+
// | uint8 | byte |
// +-------+------+
//
// 3. repeat last frame header data
//
// +---------+
// | command |
// +---------+
// |  byte   |
// +---------+
//
// 4. repeat previous frame header data
//
// +---------+------------------+
// | command | dictionary index |
// +---------+------------------+
// |  byte   |      uint8       |
// +---------+------------------+

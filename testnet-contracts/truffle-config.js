require("dotenv").config();

var HDWalletProvider = require("@truffle/hdwallet-provider");

module.exports = {
  networks: {
    develop: {
      host: "localhost",
      port: 7545, // Match default network 'ganache'
      network_id: "*",
      gas: 6721975, // 6,721,975 is truffle's default development block gas limit
      gasPrice: 200000000000
    },
    ropsten: {
      provider: function() {
        return new HDWalletProvider(
          process.env.MNEMONIC,
          "https://ropsten.infura.io/".concat(process.env.INFURA_PROJECT_ID)
        );
      },
      network_id: 3,
      gas: 6000000
    }
  },
  rpc: {
    host: "localhost",
    post: 8080
  },
  mocha: {
    useColors: true
  }
};

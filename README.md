# Cryptographic Message Syntax(CSM) using Bouncy Castle
Simple service to demonstrates how to sign a payload using a client certificate  
and verify signature using Root CA Certificate.

## Getting Started
1. Build project:
  ```bash
  ./gradlew clean build -x test 
  ```
  Note: Skipping tests as certificates might have expired  
2. Generate Certs for test:   
  ```bash
  # Generate Root CA Certificate
  ./generate_ca_cert.sh;
  
  # Generate Client Cert Signed By Root CA
  ./generate_ca_signed_cert.sh
  # Generate a Self Signed Certificate
  ./generate_self_signed_cert.sh
  ```
  Note: Update `constants.sh` if you would like to change names, paths etc.  
4. Copy generated to `src/test/resources/ssl` folder  
5. Test  
  ```bash
  ./gradle build
  ```
  you can also navigate to src/test/java/com/mamadou/CMSServiceTest.java and run that class.  
  This class has the following test cases:  
    1. Sign Content Using Client Certificate AND Verify Using CA Certificate  
    2 Sign AND Verify Content Using the Same Certificate(Self Signed Certificate)  
    3. Sign Content Using Certificate that is not signed by CA  

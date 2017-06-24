## Porting map (Java code -> Python) ##

Mapping Java files to Python packages.  
Preferred are native modules, then mature PyPI packages, then local own modules. 

Bolds are modules to port.

* ~~BinsonLight.java~~ - unused in v2     
* ~~BitField.java~~ - ctypes / bitstring / bitarray / bitstruct
* ~~Bytes.java~~  - array / struct
* **ClockTimeKeeper.java** - 
* **CryptoTestData.java**
* ~~Deserializer.java~~ - bitstring / bitstruct   
* ~~Hex.java~~ - built-in   
* ~~Io.java~~ - built-in   
* **KeyPair.java**    
* **MillisClock.java**   
* **NullTimeChecker.java**    
* **NullTimeKeeper.java**
* **Rand.java**  
* ~~Serializer.java~~ - bitstring / bitstruct
* **SystemClockTimeKeeper.java**  
* **TimeChecker.java**    
* **TimeKeeper.java** 
* **TypicalTimeChecker.java** 
* ~~Util.java~~ - unused in Python   

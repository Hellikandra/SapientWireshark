# SapientWireshark
Wireshark Lua Script to decode SAPIENT messages (in accordance to BSI Flex 335 Version 2.0 SAPIENT sCUAS) :
- [BSI Flex 335 Version 2.0](https://www.bsigroup.com/en-GB/insights-and-media/insights/brochures/bsi-flex-335-interface-of-the-sapient-sensor-management-specification/)
- [Sapient Protobuf files](https://github.com/dstl/SAPIENT-Proto-Files)

## How to install the Lua Script and run it
In Wireshark, you can the Menu Help > About Wireshark > Folders. You need to check where personal lua plugins path is :

![](Images/LuaScriptPath.png)

In the Menu Edit > Preferences > Protocols > protobuf, you need to add the folder where .proto files are. You also need to have the google .proto files on your computer.

![](Images/ProtobufFilesPath.png)

At the end, you need to select any TCP/IP message, right-click and select Decode As... If you know the port where the SAPIENT message is transmitted, you can set it here.

![](Images/DecodeAs.png)

## Tips
If you are running another version of sapient, the plugin's script need to be modified. The line `create_sapient_protobuf_dissector("SapientMessages", "SapientMessage Sapient", "sapient_msg.bsi_flex_335_v2_0.SapientMessage")` contains the correct path to the SapientMessage entrypoint.
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace NetworkApi.Business
{
    public class Utilty
    {

        public static string GetClientIP()
        {
            string retVal = "";


            if (!string.IsNullOrEmpty(HttpContext.Current.Request.ServerVariables["HTTP_CLIENT_IP"]))
                retVal = HttpContext.Current.Request.ServerVariables["HTTP_CLIENT_IP"];
            else if (!string.IsNullOrEmpty(HttpContext.Current.Request.ServerVariables["HTTP_X_FORWARDED_FOR"]))
                retVal = HttpContext.Current.Request.ServerVariables["HTTP_X_FORWARDED_FOR"];
            else if (!string.IsNullOrEmpty(HttpContext.Current.Request.ServerVariables["HTTP_X_FORWARDED"]))
                retVal = HttpContext.Current.Request.ServerVariables["HTTP_X_FORWARDED"];
            else if (!string.IsNullOrEmpty(HttpContext.Current.Request.ServerVariables["HTTP_X_CLUSTER_CLIENT_IP"]))
                retVal = HttpContext.Current.Request.ServerVariables["HTTP_X_CLUSTER_CLIENT_IP"];
            else if (!string.IsNullOrEmpty(HttpContext.Current.Request.ServerVariables["HTTP_FORWARDED_FOR"]))
                retVal = HttpContext.Current.Request.ServerVariables["HTTP_FORWARDED_FOR"];
            else if (!string.IsNullOrEmpty(HttpContext.Current.Request.ServerVariables["HTTP_FORWARDED"]))
                retVal = HttpContext.Current.Request.ServerVariables["HTTP_FORWARDED"];
            else if (!string.IsNullOrEmpty(HttpContext.Current.Request.ServerVariables["HTTP_VIA"]))
                retVal = HttpContext.Current.Request.ServerVariables["HTTP_VIA"];
            else if (!string.IsNullOrEmpty(HttpContext.Current.Request.ServerVariables["REMOTE_ADDR"]))
                retVal = HttpContext.Current.Request.ServerVariables["REMOTE_ADDR"];


            if (retVal.Contains(","))
            {
                retVal = retVal.Split(',').First();
            }
            else if (retVal.Contains(";"))
            {
                retVal = retVal.Split(';').First();
            }

            return retVal;
        }//GetClientIP

        public static string GetServerInternalIP()
        {

            IPHostEntry host = Dns.GetHostEntry(Dns.GetHostName());
            return host.AddressList.FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork).ToString();

        }

        public static string GetServerExternalIP()
        {
            try
            {
                //http://jsonip.com
                //http://smart-ip.net/geoip-json?callback=?                
                //http://jsonip.appspot.com?callback=?
                //http://l2.io/ip
                //<script type="text/javascript" src="http://l2.io/ip.js?var=myip"></script>
                //http://checkip.dyndns.org


                // check IP using DynDNS's service
                WebRequest request = WebRequest.Create("http://checkip.dyndns.org");
                WebResponse response = request.GetResponse();
                StreamReader stream = new StreamReader(response.GetResponseStream());

                // IMPORTANT: set Proxy to null, to drastically INCREASE the speed of request
                request.Proxy = null;

                // read complete response
                string ipAddress = stream.ReadToEnd();

                // replace everything and keep only IP
                return ipAddress.
                    Replace("<html><head><title>Current IP Check</title></head><body>Current IP Address: ", string.Empty).
                    Replace("</body></html>", string.Empty);
            }
            catch
            {

                return string.Empty;
            }
        }

        public static bool CheckNetworkAvailable()
        {
            return NetworkInterface.GetIsNetworkAvailable();
        }

        public static bool IsLocal()
        {
            return HttpContext.Current.Request.IsLocal;
        }

        public static bool IsInternalIP(string IP)
        {
            // If the IP is the localhost address then return true.
            if (IP == "127.0.0.1" || IP == "::1")
                return true;

            try
            {
                // Check to see if the IP is a valid private network address.
                uint addr = IPStringToUint(IP);

                if (addr >= IPStringToUint("10.0.0.0") && addr <= IPStringToUint("10.255.255.255"))
                    return true;

                if (addr >= IPStringToUint("192.168.0.0") && addr <= IPStringToUint("192.168.255.255"))
                    return true;

                if (addr >= IPStringToUint("172.16.0.0") && addr <= IPStringToUint("172.31.255.255"))
                    return true;

                // If its not matched any of the private network addresses, then return false.
                return false;
            }
            catch (FormatException)
            {
                return false;
            }
            catch (ArgumentException)
            {
                return false;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="IP"></param>
        /// <remarks>A null or empty string passed as the ipAddress will return true. An invalid ipAddress will be returned as true. </remarks>
        /// <returns></returns>
        public static bool IsNonRoutableIpAddress(string IP)
        {
            //Reference: http://en.wikipedia.org/wiki/Reserved_IP_addresses

            //if the ip address string is empty or null string, we consider it to be non-routable
            if (String.IsNullOrEmpty(IP))
            {
                return true;
            }

            //if we cannot parse the Ipaddress, then we consider it non-routable
            IPAddress tempIpAddress = null;
            if (!IPAddress.TryParse(IP, out tempIpAddress))
            {
                return true;
            }

            byte[] ipAddressBytes = tempIpAddress.GetAddressBytes();

            //if ipAddress is IPv4
            if (tempIpAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                if (IsIpAddressInRange(ipAddressBytes, "10.0.0.0/8")) //Class A Private network check
                {
                    return true;
                }
                else if (IsIpAddressInRange(ipAddressBytes, "172.16.0.0/12")) //Class B private network check
                {
                    return true;
                }
                else if (IsIpAddressInRange(ipAddressBytes, "192.168.0.0/16")) //Class C private network check
                {
                    return true;
                }
                else if (IsIpAddressInRange(ipAddressBytes, "127.0.0.0/8")) //Loopback
                {
                    return true;
                }
                else if (IsIpAddressInRange(ipAddressBytes, "0.0.0.0/8"))   //reserved for broadcast messages
                {
                    return true;
                }

                //its routable if its ipv4 and meets none of the criteria
                return false;
            }
            //if ipAddress is IPv6
            else if (tempIpAddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                //incomplete
                if (IsIpAddressInRange(ipAddressBytes, "::/128"))       //Unspecified address
                {
                    return true;
                }
                else if (IsIpAddressInRange(ipAddressBytes, "::1/128"))     //lookback address for localhost
                {
                    return true;
                }
                else if (IsIpAddressInRange(ipAddressBytes, "2001:db8::/32"))   //Addresses used in documentation
                {
                    return true;
                }

                return false;
            }
            else
            {
                //we default to non-routable if its not Ipv4 or Ipv6
                return true;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="ipAddressBytes"></param>
        /// <param name="reservedIpAddress"></param>
        /// <returns></returns>
        private static bool IsIpAddressInRange(byte[] ipAddressBytes, string reservedIpAddress)
        {
            if (String.IsNullOrEmpty(reservedIpAddress))
            {
                return false;
            }

            if (ipAddressBytes == null)
            {
                return false;
            }

            //Split the reserved ip address into a bitmask and ip address
            string[] ipAddressSplit = reservedIpAddress.Split(new char[] { '/' }, StringSplitOptions.RemoveEmptyEntries);
            if (ipAddressSplit.Length != 2)
            {
                return false;
            }

            string ipAddressRange = ipAddressSplit[0];

            IPAddress ipAddress = null;
            if (!IPAddress.TryParse(ipAddressRange, out ipAddress))
            {
                return false;
            }

            // Convert the IP address to bytes.
            byte[] ipBytes = ipAddress.GetAddressBytes();

            //parse the bits
            int bits = 0;
            if (!int.TryParse(ipAddressSplit[1], out bits))
            {
                bits = 0;
            }

            // BitConverter gives bytes in opposite order to GetAddressBytes().
            byte[] maskBytes = null;
            if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
            {
                uint mask = ~(uint.MaxValue >> bits);
                maskBytes = BitConverter.GetBytes(mask).Reverse().ToArray();
            }
            else if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
            {
                //128 places
                BitArray bitArray = new BitArray(128, false);

                //shift <bits> times to the right
                ShiftRight(bitArray, bits, true);

                //turn into byte array
                maskBytes = ConvertToByteArray(bitArray).Reverse().ToArray();
            }


            bool result = true;

            //Calculate
            for (int i = 0; i < ipBytes.Length; i++)
            {
                result &= (byte)(ipAddressBytes[i] & maskBytes[i]) == ipBytes[i];

            }

            return result;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="bitArray"></param>
        /// <param name="shiftN"></param>
        /// <param name="fillValue"></param>
        private static void ShiftRight(BitArray bitArray, int shiftN, bool fillValue)
        {
            for (int i = shiftN; i < bitArray.Count; i++)
            {
                bitArray[i - shiftN] = bitArray[i];
            }

            //fill the shifted bits as false
            for (int index = bitArray.Count - shiftN; index < bitArray.Count; index++)
            {
                bitArray[index] = fillValue;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="bitArray"></param>
        /// <returns></returns>
        private static byte[] ConvertToByteArray(BitArray bitArray)
        {
            // pack (in this case, using the first bool as the lsb - if you want
            // the first bool as the msb, reverse things ;-p)
            int bytes = (bitArray.Length + 7) / 8;
            byte[] arr2 = new byte[bytes];
            int bitIndex = 0;
            int byteIndex = 0;

            for (int i = 0; i < bitArray.Length; i++)
            {
                if (bitArray[i])
                {
                    arr2[byteIndex] |= (byte)(1 << bitIndex);
                }

                bitIndex++;
                if (bitIndex == 8)
                {
                    bitIndex = 0;
                    byteIndex++;
                }
            }

            return arr2;
        }

        private static uint IPStringToUint(string IP)
        {
            byte[] bytes = IPAddress.Parse(IP).GetAddressBytes();
            return (uint)IPAddress.HostToNetworkOrder(BitConverter.ToUInt32(bytes, 0));
        }

        public static void RegisterClientScriptBlock(System.Web.UI.Page page, string script, bool addScriptTag = true, string scriptName = "script1")
        {
            //<body>
            //<form>
            //here is RegisterClientScriptBlock

            //my controls
            //my controls
            //my controls

            //</form>
            //</body>
            System.Web.UI.ClientScriptManager cs = page.ClientScript;


            Type cstype = page.GetType();

            // Check to see if the startup script is already registered.
            if (!cs.IsClientScriptBlockRegistered(cstype, scriptName))
            {
                cs.RegisterClientScriptBlock(cstype, scriptName, script, addScriptTag);
            }

        }
        public static void RegisterStartupScript(System.Web.UI.Page page, string script, bool addScriptTag = true, string scriptName = "script1")
        {
            //<body>
            //<form>
            

            //my controls
            //my controls
            //my controls

            //here is RegisterStartupScript
            //</form>
            //</body>
            System.Web.UI.ClientScriptManager cs = page.ClientScript;

            Type cstype = page.GetType();

            // Check to see if the startup script is already registered.
            if (!cs.IsStartupScriptRegistered(cstype, scriptName))
            {
                cs.RegisterStartupScript(cstype, scriptName, script, addScriptTag);
            }

        }

        public static void RegisterHiddenField(System.Web.UI.Page page, string name, string value)
        {
            System.Web.UI.ClientScriptManager cs = page.ClientScript;

            cs.RegisterHiddenField(name, value);

        }

    }
}

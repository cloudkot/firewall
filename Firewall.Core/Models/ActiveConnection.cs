public class ActiveConnection
{
    public string Protocol { get; set; }       // TCP / UDP
    public string LocalAddress { get; set; }   // IP:port
    public string RemoteAddress { get; set; }
    public string State { get; set; }          // LISTEN, ESTABLISHED и т.д.
    public int PID { get; set; }
    public string ProcessName { get; set; }
}
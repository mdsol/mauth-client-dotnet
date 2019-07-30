namespace Medidata.MAuth.Core
{
    internal class MAuthCoreFactory
    {
        public static IMAuthCore Instantiate()
        {
            return new MAuthCore();
        }
    }
}

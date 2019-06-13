[![Build](https://img.shields.io/travis/TankerHQ/identity-cs/master.svg)](https://travis-ci.org/TankerHQ/identity-cs)

# Identity

Identity generation using .Net for the [Tanker SDK](https://tanker.io/docs/latest).


## Installation

You can install it from [NuGet](https://www.nuget.org/packages/Tanker.Identity).

## Usage

```csharp

using System;

namespace App
{
    class Program
    {
        static void Main(string[] args)
        {
            var aliceIdentity = Tanker.Identity.CreateIdentity(@"<your trustchainId>", @"<your trustchain private key>", @"<some user Id>");
            Console.WriteLine(aliceIdentity);
            Console.ReadKey(true);
        }
    }
}

```


## Going further

Read more about user tokens in the [Tanker guide](https://tanker.io/docs/latest/guide/server).

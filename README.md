# tangent

A simple programming language. Not completed yet.
Inspired by odin and transpiled to C/C++;

```
add :: (a:int,b:int) int
{
    return a+b;
}

main :: proc()
{
    count:int = 0;

    name := "tangent"; //type inference
    
    for
    {
        print("Infinite loop");
    }

    // C style for loop
    for i:= 0; i < 10 ; i+=1
    {
        print(i);
    }
    

    for i in  0..10
    {
    }

    print("Hello world");
}
```

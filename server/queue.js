(function(){function b(b){function n(){if(d&&j<b){var a=d,l=a[0],k=Array.prototype.slice.call(a,1),m=a.index;d=d===c?c=null:d.next;++j;k.splice(k.indexOf(e.D),1,function(a,b){--j;g||(a?f&&h(g=a,f=i=d=c=null):(i[m]=b,--f?n():h(null,i)))});l.apply(null,k)}}var e={},j=0,f=0,l=-1,d,c,g=null,i=[],h=m;e.D={};b=b||Infinity;e.defer=function(){if(!g){var a=arguments;a.index=++l;c?(c.next=a,c=c.next):d=c=a;++f;n()}return e};e.await=function(a){h=a;f||h(g,i);return e};return e}function m(){}"undefined"===typeof module?
self.queue=b:module.exports=b;b.version="0.0.1"})();